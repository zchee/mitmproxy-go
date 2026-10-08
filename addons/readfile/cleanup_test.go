// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package readfile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/zchee/mitmproxy-go/master"
)

type gatedClosePipe struct {
	*os.File
	entered, release, loaded chan struct{}
	observeClose             func()
	once                     sync.Once
	err                      error
}

func (p *gatedClosePipe) Close() error {
	p.once.Do(func() {
		if p.observeClose != nil {
			p.observeClose()
		}
		close(p.entered)
		<-p.release
		p.err = p.File.Close()
		close(p.loaded)
	})
	return p.err
}

func TestDoneCloseOutsideDispatch(t *testing.T) {
	input, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close(); _ = output.Close() })
	var held, closeHeld atomic.Bool
	m := master.New(master.Config{
		OnDispatchStart: func() { held.Store(true) },
		OnDispatchEnd:   func() { held.Store(false) },
	})
	t.Cleanup(func() {
		cleanupCtx, stopCleanup := context.WithTimeout(context.WithoutCancel(t.Context()), cleanupTimeout)
		defer stopCleanup()
		_ = m.Close(cleanupCtx)
	})
	pipe := &gatedClosePipe{
		File: input, entered: make(chan struct{}), release: make(chan struct{}), loaded: make(chan struct{}),
		observeClose: func() { closeHeld.Store(held.Load()) },
	}
	release := sync.OnceFunc(func() { close(pipe.release) })
	t.Cleanup(release)
	r := New(m, Config{Stdin: pipe})
	if err := m.Addons.Add(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	r.cancel, r.closer, r.done = func() {}, pipe, pipe.loaded
	stopped := make(chan struct{})
	var stopErr error
	go func() {
		stopErr = m.Do(t.Context(), r.Done)
		close(stopped)
	}()
	wait(t, pipe.entered)
	if closeHeld.Load() {
		t.Error("Done retained dispatch while the stdin Close was pending")
	} else if err := m.Do(t.Context(), func(context.Context) error { return nil }); err != nil {
		t.Errorf("dispatch during Close: %v", err)
	}
	release()
	wait(t, stopped)
	if stopErr != nil {
		t.Errorf("Done: %v", stopErr)
	}
}

func TestDoneCleanupBoundAndRestart(t *testing.T) {
	tests := map[string]struct{ cancelCaller bool }{
		"caller cancellation": {cancelCaller: true},
		"cleanup budget":      {},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				input, output, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = input.Close(); _ = output.Close() })
				pipe := &gatedClosePipe{File: input, entered: make(chan struct{}), release: make(chan struct{}), loaded: make(chan struct{})}
				m, r, _ := newReader(t, pipe)
				if err := configure(t, m, map[string]any{"rfile": new("-")}); err != nil {
					t.Fatal(err)
				}
				r.cancel, r.closer, r.done = func() {}, pipe, pipe.loaded
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				stopped := make(chan error, 1)
				go func() { stopped <- m.Do(ctx, r.Done) }()
				<-pipe.entered
				want := error(context.DeadlineExceeded)
				if test.cancelCaller {
					want = context.Canceled
					cancel()
				} else {
					time.Sleep(5 * time.Second)
				}
				if err := <-stopped; !errors.Is(err, want) || !test.cancelCaller && !strings.Contains(err.Error(), "stop loader") {
					t.Errorf("Done = %v, want %v", err, want)
				}
				inspectionCtx, stopInspection := context.WithTimeout(context.WithoutCancel(t.Context()), cleanupTimeout)
				defer stopInspection()
				var cleanup *loaderCleanup
				if err := m.Do(inspectionCtx, func(ctx context.Context) error {
					cleanup = r.cleanup
					if cleanup == nil || r.cancel != nil || r.closer != nil {
						t.Error("cancelled loader was not transferred to its cleanup owner")
					}
					if err := r.Running(ctx); err == nil || !strings.Contains(err.Error(), "cleanup is still pending") {
						t.Errorf("Running during pending cleanup = %v", err)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				err = m.Do(inspectionCtx, func(ctx context.Context) error {
					ctx, cancel := context.WithCancel(ctx)
					cancel()
					return r.Done(ctx)
				})
				if !errors.Is(err, context.Canceled) {
					t.Errorf("repeated Done = %v, want context canceled", err)
				}
				if err := m.Do(inspectionCtx, func(context.Context) error {
					if r.cleanup != cleanup {
						t.Error("repeated Done replaced the unfinished cleanup owner")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				select {
				case <-cleanup.finished:
					t.Error("cleanup timeout was treated as successful joining")
				default:
				}
				close(pipe.release)
				<-cleanup.finished
				path := filepath.Join(t.TempDir(), "empty.flows")
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := configure(t, m, map[string]any{"rfile": new(path)}); err != nil {
					t.Fatal(err)
				}
				var loaded <-chan struct{}
				if err := m.Do(t.Context(), func(ctx context.Context) error {
					if err := r.Running(ctx); err != nil {
						return err
					}
					loaded = r.done
					if r.cleanup != nil || loaded == pipe.loaded {
						t.Error("completed cleanup prevented a fresh loader")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				<-loaded
			})
		})
	}
}

func TestDoneSynchronousRemoval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		input, output, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = input.Close(); _ = output.Close() })
		pipe := &gatedClosePipe{File: input, entered: make(chan struct{}), release: make(chan struct{}), loaded: make(chan struct{})}
		m, r, _ := newReader(t, pipe)
		r.cancel, r.closer, r.done = func() {}, pipe, pipe.loaded
		if err := m.Addons.Remove(t.Context(), r); err != nil {
			t.Fatal(err)
		}
		<-pipe.entered
		var cleanup *loaderCleanup
		if err := m.Do(t.Context(), func(context.Context) error { cleanup = r.cleanup; return nil }); err != nil {
			t.Fatal(err)
		}
		close(pipe.release)
		<-cleanup.finished
	})
}

type observedReadPipe struct {
	*os.File
	reads int
}

func (p *observedReadPipe) Read(buf []byte) (int, error) {
	p.reads++
	return p.File.Read(buf)
}

type completedClosePipe struct {
	*os.File
	closed chan struct{}
}

func (p *completedClosePipe) Close() error {
	err := p.File.Close()
	close(p.closed)
	return err
}

func TestCleanupWaitsForLoader(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		input, output, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = input.Close(); _ = output.Close() })
		pipe := &completedClosePipe{File: input, closed: make(chan struct{})}
		loaded := make(chan struct{})
		cleanup := &loaderCleanup{closer: pipe, loaded: loaded, finished: make(chan struct{})}
		cleanup.start()
		<-pipe.closed
		select {
		case <-cleanup.finished:
			t.Error("Close completion was mistaken for loader completion")
		default:
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := cleanup.wait(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("pending loader wait = %v, want context canceled", err)
		}
		cleanup.start()
		close(loaded)
		<-cleanup.finished
		if err := cleanup.wait(t.Context()); err != nil {
			t.Errorf("completed cleanup: %v", err)
		}
	})
}

func TestLoadFlowsCanceledBeforeRead(t *testing.T) {
	input, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close(); _ = output.Close() })
	if _, err := output.Write([]byte("invalid")); err != nil {
		t.Fatal(err)
	}
	_, r, logs := newReader(t, input)
	ctx, cancel := context.WithCancelCause(t.Context())
	want := errors.New("loading stopped")
	cancel(want)
	observed := &observedReadPipe{File: input}
	count, err := r.LoadFlows(ctx, observed)
	if !errors.Is(err, want) || count != 0 || observed.reads != 0 || logs.Len() != 0 {
		t.Fatalf("cancelled loading = count %d, error %v, reads %d, log %q", count, err, observed.reads, logs.String())
	}
}
