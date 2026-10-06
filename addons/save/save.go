// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package save streams completed flows to mitmproxy dump files.
package save

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	timefmt "github.com/itchyny/timefmt-go"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/privfile"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

// Save writes finished flows and flushes active flows on shutdown. All hooks
// and commands must run under the addon dispatch lock. File writes deliberately
// block under that lock, as upstream blocks its event loop while recording.
type Save struct {
	options     *options.Manager
	filter      filter.Expr
	file        *os.File
	stream      *flowio.Writer
	currentPath string
	active      map[flow.Flow]struct{}
	stderr      io.Writer
	fatal       func(error)
	fatalOnce   sync.Once
	clock       func() time.Time
}

// New returns a storage addon using opts. A failure to write the stream file
// prints upstream's line on standard error and calls fatal once with a
// [*master.ExitError] carrying exit status 1, the way upstream crashes
// visibly instead of letting traffic through unrecorded; the program passes
// the master's fatal shutdown here. A nil fatal drops the notification; the
// failure is still returned to the dispatcher.
func New(opts *options.Manager, fatal func(error)) *Save {
	return &Save{options: opts, active: make(map[flow.Flow]struct{}), stderr: os.Stderr, fatal: fatal, clock: time.Now}
}

// Load registers the stream options and save.file command.
func (s *Save) Load(ctx context.Context, loader *addon.Loader) error {
	if err := loader.AddOption(ctx, "save_stream_file", options.TypeOptStr, nil, `
            Stream flows to file as they arrive. Prefix path with + to append.
            The full path can use python strftime() formating, missing
            directories are created as needed. A new file is opened every time
            the formatted string changes.
            `); err != nil {
		return err
	}
	if err := loader.AddOption(ctx, "save_stream_filter", options.TypeOptStr, nil, "Filter which flows are written to file."); err != nil {
		return err
	}
	return loader.AddCommand("save.file", s.save, command.WithParams("flows", "path"), command.WithHelp("Save flows to a file. If the path starts with a +, flows are\nappended to the file, otherwise it is over-written."))
}

// Configure compiles the filter and opens or closes the configured stream.
func (s *Save) Configure(ctx context.Context, updated map[string]struct{}) error {
	_, filterChanged := updated["save_stream_filter"]
	_, pathChanged := updated["save_stream_file"]
	if filterChanged {
		var expr filter.Expr
		if spec := s.options.OptStr("save_stream_filter"); spec != nil && *spec != "" {
			var err error
			expr, err = filter.Parse(*spec)
			if err != nil {
				return &options.OptionsError{Err: err}
			}
		}
		s.filter = expr
	}
	if !filterChanged && !pathChanged {
		return nil
	}
	if path := s.options.OptStr("save_stream_file"); path != nil && *path != "" {
		if err := s.rotate(); err != nil {
			return &options.OptionsError{Err: err}
		}
		return nil
	}
	return s.Done(ctx)
}

// pathMode splits a path specification into the path and the open flags, as
// upstream's _path and _mode read it: a "+" prefix appends instead of
// overwriting, and a "~" or "~user" prefix expands to that home directory,
// staying unchanged for an unknown user as Python's expanduser does.
func pathMode(spec string) (string, int) {
	flag := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if rest, ok := strings.CutPrefix(spec, "+"); ok {
		spec = rest
		flag = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	}
	if strings.HasPrefix(spec, "~") {
		name, rest, _ := strings.Cut(spec[1:], string(filepath.Separator))
		var home string
		var err error
		if name == "" {
			home, err = os.UserHomeDir()
		} else {
			var account *user.User
			account, err = user.Lookup(name)
			if err == nil {
				home = account.HomeDir
			}
		}
		if err == nil {
			spec = filepath.Join(home, rest)
		}
	}
	return spec, flag
}

// Upstream formats a naive datetime, so timezone directives render empty.
// Match escaped percent pairs first to preserve literal "%z" and "%Z".
var naiveTimezone = strings.NewReplacer("%%", "%%", "%z", "", "%Z", "")

func (s *Save) rotate() error {
	spec := s.options.OptStr("save_stream_file")
	if spec == nil || *spec == "" {
		return nil
	}
	path, mode := pathMode(*spec)
	// The path promises Python strftime formatting in local time, as
	// upstream's datetime.today().strftime does; a new file is opened
	// every time the formatted string changes.
	path = timefmt.Format(s.clock(), naiveTimezone.Replace(path))
	if s.currentPath == path && s.stream != nil {
		return nil
	}
	if s.file != nil {
		err := s.file.Close()
		s.file, s.stream = nil, nil
		if err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil { //nolint:gosec // The process umask decides, as it does for Python's mkdir(parents=True).
		return err
	}
	open := privfile.Create
	if mode&os.O_APPEND != 0 {
		open = privfile.Append
	}
	file, err := open(path)
	if err != nil {
		return err
	}
	s.file, s.stream, s.currentPath = file, flowio.NewWriter(file), path
	return nil
}

func (s *Save) write(f flow.Flow) error {
	if s.filter != nil && !filter.Match(s.filter, f) {
		return nil
	}
	return s.stream.Add(f)
}

func (s *Save) saveFlow(f flow.Flow) error {
	if s.stream == nil {
		return nil
	}
	err := s.rotate()
	if err == nil {
		err = s.write(f)
	}
	if err != nil {
		return s.failed(err)
	}
	delete(s.active, f)
	return nil
}

func (s *Save) failed(cause error) error {
	_, stderrErr := fmt.Fprintf(s.stderr, "Error while writing to %s: %s", s.currentPath, cause)
	if s.file != nil {
		_ = s.file.Close()
	}
	s.file, s.stream = nil, nil
	clear(s.active)
	exit := &master.ExitError{Err: errors.Join(fmt.Errorf("error while writing to %s: %w", s.currentPath, cause), stderrErr)}
	if s.fatal != nil {
		s.fatalOnce.Do(func() { s.fatal(exit) })
	}
	return exit
}

// Done saves active flows and closes the current stream. Repeated calls do
// nothing. A write failure reaches the fatal callback given to [New] and is
// returned as a master.ExitError, never os.Exit.
func (s *Save) Done(context.Context) error {
	if s.stream == nil {
		return nil
	}
	for f := range s.active {
		if err := s.write(f); err != nil {
			return s.failed(err)
		}
	}
	clear(s.active)
	if err := s.file.Close(); err != nil {
		return s.failed(err)
	}
	s.file, s.stream, s.currentPath = nil, nil, ""
	return nil
}

func (s *Save) save(ctx context.Context, flows []flow.Flow, spec command.Path) error {
	path, mode := pathMode(string(spec))
	open := privfile.Create
	if mode&os.O_APPEND != 0 {
		open = privfile.Append
	}
	file, err := open(path)
	if err != nil {
		return &command.Error{Err: err}
	}
	writer := flowio.NewWriter(file)
	for _, f := range flows {
		if err := writer.Add(f); err != nil {
			return &command.Error{Err: errors.Join(err, file.Close())}
		}
	}
	if err := file.Close(); err != nil {
		return &command.Error{Err: err}
	}
	if strings.HasSuffix(string(spec), ".har") || strings.HasSuffix(string(spec), ".zhar") {
		slog.Log(ctx, addon.LevelAlert, "Saved as mitmproxy dump file. To save HAR files, use the `save.har` command.")
	} else {
		slog.Log(ctx, addon.LevelAlert, fmt.Sprintf("Saved %d flows.", len(flows)))
	}
	return nil
}

func (s *Save) start(f flow.Flow) {
	if s.stream != nil {
		s.active[f] = struct{}{}
	}
}

// Request tracks an active HTTP flow for shutdown flushing.
func (s *Save) Request(_ context.Context, f *flow.HTTPFlow) error { s.start(f); return nil }

// Response saves an HTTP flow unless WebSocketEnd will save it later.
func (s *Save) Response(_ context.Context, f *flow.HTTPFlow) error {
	if f.WebSocket != nil {
		return nil
	}
	return s.saveFlow(f)
}

// Error saves a failed HTTP flow.
func (s *Save) Error(ctx context.Context, f *flow.HTTPFlow) error { return s.Response(ctx, f) }

// WebSocketEnd saves the HTTP handshake and all WebSocket messages together.
func (s *Save) WebSocketEnd(_ context.Context, f *flow.HTTPFlow) error { return s.saveFlow(f) }

// TCPStart tracks an active TCP flow for shutdown flushing.
func (s *Save) TCPStart(_ context.Context, f *flow.TCPFlow) error { s.start(f); return nil }

// TCPEnd saves a finished TCP flow.
func (s *Save) TCPEnd(_ context.Context, f *flow.TCPFlow) error { return s.saveFlow(f) }

// TCPError saves a failed TCP flow.
func (s *Save) TCPError(ctx context.Context, f *flow.TCPFlow) error { return s.TCPEnd(ctx, f) }

// UDPStart tracks an active UDP flow for shutdown flushing.
func (s *Save) UDPStart(_ context.Context, f *flow.UDPFlow) error { s.start(f); return nil }

// UDPEnd saves a finished UDP flow.
func (s *Save) UDPEnd(_ context.Context, f *flow.UDPFlow) error { return s.saveFlow(f) }

// UDPError saves a failed UDP flow.
func (s *Save) UDPError(ctx context.Context, f *flow.UDPFlow) error { return s.UDPEnd(ctx, f) }

// DNSRequest tracks an active DNS flow for shutdown flushing.
func (s *Save) DNSRequest(_ context.Context, f *flow.DNSFlow) error { s.start(f); return nil }

// DNSResponse saves a finished DNS flow.
func (s *Save) DNSResponse(_ context.Context, f *flow.DNSFlow) error { return s.saveFlow(f) }

// DNSError saves a failed DNS flow.
func (s *Save) DNSError(_ context.Context, f *flow.DNSFlow) error { return s.saveFlow(f) }
