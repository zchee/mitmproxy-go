// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package readfile replays recorded flow files through the proxy's hooks.
package readfile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

// Config configures a [ReadFile].
type Config struct {
	// Stdin is the stream the rfile value "-" reads. Nil means os.Stdin.
	// Loading from it transfers its ownership: the done hook closes it to
	// release a blocked read, and loading closes it when the stream ends.
	Stdin io.ReadCloser

	// Logger receives loading failures. Nil means [slog.Default] at the time
	// of each record.
	Logger *slog.Logger
}

// ReadFile loads the flows of the rfile option on its own goroutine once the
// proxy is running, porting mitmproxy's ReadFile and ReadFileStdin. Its
// mutable state is guarded by the dispatch lock: options change through
// configure, and loading reads the filter inside the master's dispatch.
type ReadFile struct {
	master *master.Master
	stdin  io.ReadCloser
	logger *slog.Logger

	// The fields below are only accessed under the dispatch lock.
	filter filter.Expr
	cancel context.CancelFunc
	closer io.Closer
	done   chan struct{}
}

// New returns a flow file reader that replays flows through m.
func New(m *master.Master, cfg Config) *ReadFile {
	if cfg.Stdin == nil {
		cfg.Stdin = os.Stdin
	}
	return &ReadFile{master: m, stdin: cfg.Stdin, logger: cfg.Logger}
}

// Name identifies the addon, as upstream's readfile does.
func (*ReadFile) Name() string { return "readfile" }

// Load registers the rfile and readfile_filter options and the
// readfile.reading command.
func (r *ReadFile) Load(ctx context.Context, loader *addon.Loader) error {
	if err := loader.AddOption(ctx, "rfile", options.TypeOptStr, nil, "Read flows from file."); err != nil {
		return err
	}
	if err := loader.AddOption(ctx, "readfile_filter", options.TypeOptStr, nil, "Read only matching flows."); err != nil {
		return err
	}
	return loader.AddCommand("readfile.reading", r.Reading)
}

// Configure parses readfile_filter; an invalid expression rolls the change
// back and an absent or empty one clears the filter.
func (r *ReadFile) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, ok := updated["readfile_filter"]; !ok {
		return nil
	}
	expression := r.master.Options.OptStr("readfile_filter")
	if expression == nil || *expression == "" {
		r.filter = nil
		return nil
	}
	parsed, err := filter.Parse(*expression)
	if err != nil {
		return &options.OptionsError{Msg: err.Error(), Err: err}
	}
	r.filter = parsed
	return nil
}

// Running starts loading the rfile flows on a new goroutine and returns
// without waiting for them, so later running handlers observe flows still
// arriving. The goroutine runs outside dispatch until the done hook joins it.
func (r *ReadFile) Running(ctx context.Context) error {
	path := r.master.Options.OptStr("rfile")
	if path == nil || *path == "" {
		return nil
	}
	// The loader must not inherit the hook's dispatch frame, which goes stale
	// when this hook chain releases the lock, nor its cancellation, which ends
	// with the hook. Concurrent hands out a frame-free context carrying the
	// caller's values; a synchronous dispatch cannot release the lock, so the
	// loader starts from a fresh context there.
	base := context.Background()
	if next, err := addon.Concurrent(ctx, func(clean context.Context) error {
		base = context.WithoutCancel(clean)
		return nil
	}); err == nil {
		ctx = next
	}
	_ = ctx
	loadCtx, cancel := context.WithCancel(base)
	if r.cancel != nil {
		r.cancel()
	}
	r.cancel = cancel
	r.closer = nil
	if *path == "-" {
		r.closer = r.stdin
	}
	done := make(chan struct{})
	r.done = done
	go r.read(loadCtx, *path, done)
	return nil
}

// Done stops a running loader: it cancels loading, closes a stdin stream a
// blocked read holds, and joins the goroutine with the dispatch lock
// released. A done fired synchronously by an addon removal cannot release
// the lock and leaves the cancelled goroutine to finish on its own.
func (r *ReadFile) Done(ctx context.Context) error {
	cancel, closer, done := r.cancel, r.closer, r.done
	r.cancel, r.closer = nil, nil
	if cancel == nil {
		return nil
	}
	cancel()
	if closer != nil {
		_ = closer.Close()
	}
	if _, err := addon.Concurrent(ctx, func(context.Context) error {
		<-done
		return nil
	}); err != nil && !errors.Is(err, addon.ErrSyncContext) {
		return err
	}
	return nil
}

// Reading reports whether flows are still being loaded, as the
// readfile.reading command.
func (r *ReadFile) Reading(context.Context) bool {
	if r.done == nil {
		return false
	}
	select {
	case <-r.done:
		return false
	default:
		return true
	}
}

// LoadFlowsFromPath loads the flows of the file at path, expanding a leading
// ~ as Python's expanduser does; "-" reads the configured stdin stream and
// closes it. Call it outside dispatch. It returns the number of flows loaded
// alongside any failure.
func (r *ReadFile) LoadFlowsFromPath(ctx context.Context, path string) (count int, err error) {
	var src io.ReadCloser
	if path == "-" {
		src = r.stdin
	} else {
		if expanded, perr := command.PathType.Parse(ctx, r.master.Commands, path); perr == nil {
			path = string(expanded.(command.Path))
		}
		file, oerr := os.Open(path) //nolint:gosec // Reading the flow file the rfile option names is the point.
		if oerr != nil {
			r.log(ctx, slog.LevelError, fmt.Sprintf("Cannot load flows: %v", oerr))
			return 0, oerr
		}
		src = file
	}
	defer func() {
		if cerr := src.Close(); err == nil && ctx.Err() == nil {
			err = cerr
		}
	}()
	return r.LoadFlows(ctx, src)
}

// LoadFlows replays every flow of src that matches the readfile_filter
// option through the master's hooks and returns how many loaded. Call it
// outside dispatch; filter matching runs under it. A read failure after the
// first loaded flow is logged as a corruption warning naming the count, an
// immediate one as an error, and both are returned; a cancelled context
// returns its cause silently.
func (r *ReadFile) LoadFlows(ctx context.Context, src io.Reader) (int, error) {
	count := 0
	reader := flowio.NewReader(src)
	for {
		f, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return count, context.Cause(ctx)
			}
			if count > 0 {
				r.log(ctx, slog.LevelWarn, fmt.Sprintf("Flow file corrupted - loaded %d flows.", count))
			} else {
				r.log(ctx, slog.LevelError, "Flow file corrupted.")
			}
			return count, err
		}
		match := true
		if err := r.master.Do(ctx, func(context.Context) error {
			if r.filter != nil {
				match = filter.Match(r.filter, f)
			}
			return nil
		}); err != nil {
			return count, err
		}
		if !match {
			continue
		}
		if err := r.master.LoadFlow(ctx, f); err != nil {
			return count, err
		}
		count++
	}
}

func (r *ReadFile) read(ctx context.Context, path string, done chan struct{}) {
	defer close(done)
	if _, err := r.LoadFlowsFromPath(ctx, path); err != nil && ctx.Err() == nil {
		r.log(ctx, slog.LevelError, fmt.Sprintf("Failed to read %s: %v", path, err))
	}
}

func (r *ReadFile) log(ctx context.Context, level slog.Level, message string) {
	logger := r.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Log(ctx, level, message)
}
