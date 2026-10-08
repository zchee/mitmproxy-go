// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package addon

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// deadlockTimeout bounds every test step that would hang on a deadlock.
const deadlockTimeout = 30 * time.Second

// within runs fn on its own goroutine and fails the test when fn has not
// returned after deadlockTimeout.
func within(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(deadlockTimeout):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("%s did not finish; the dispatch lock is probably deadlocked:\n%s", what, buf[:n])
	}
}

// capturePanic runs fn and returns the value it panicked with, or nil.
func capturePanic(fn func()) (r any) {
	defer func() { r = recover() }()
	fn()
	return nil
}

// countingDispatcher returns a dispatcher whose watchdog callbacks count
// acquisitions and releases of the lock. The counters are only touched with
// the lock held, so reading them after the dispatch is over needs no
// synchronisation of its own.
func countingDispatcher() (d *dispatcher, starts, ends *int) {
	starts, ends = new(int), new(int)
	d = &dispatcher{
		onStart: func() { *starts++ },
		onEnd:   func() { *ends++ },
	}
	return d, starts, ends
}

func TestDispatchReentry(t *testing.T) {
	d, starts, ends := countingDispatcher()
	var depths []int
	within(t, "re-entrant dispatch", func() {
		err := d.do(t.Context(), func(ctx context.Context) error {
			depths = append(depths, frameFrom(ctx).depth)
			return d.do(ctx, func(ctx context.Context) error {
				depths = append(depths, frameFrom(ctx).depth)
				return d.do(ctx, func(ctx context.Context) error {
					depths = append(depths, frameFrom(ctx).depth)
					return nil
				})
			})
		})
		if err != nil {
			t.Errorf("do: %v", err)
		}
	})
	if want := []int{1, 2, 3}; !slices.Equal(depths, want) {
		t.Errorf("frame depths = %v, want %v", depths, want)
	}
	if *starts != 1 || *ends != 1 {
		t.Errorf("lock acquired %d times and released %d times, want once each", *starts, *ends)
	}
}

func TestDispatchSerialisesHolders(t *testing.T) {
	d := &dispatcher{}
	const holders = 16
	var (
		inside int // only touched under the dispatch lock
		maxIn  int
		wg     sync.WaitGroup
	)
	for range holders {
		wg.Go(func() {
			err := d.do(t.Context(), func(context.Context) error {
				inside++
				maxIn = max(maxIn, inside)
				inside--
				return nil
			})
			if err != nil {
				t.Errorf("do: %v", err)
			}
		})
	}
	within(t, "concurrent holders", wg.Wait)
	if maxIn != 1 {
		t.Errorf("%d holders ran at once, want 1", maxIn)
	}
}

func TestDispatchErrorPassesThrough(t *testing.T) {
	d := &dispatcher{}
	errHook := errors.New("hook failed")
	if err := d.do(t.Context(), func(context.Context) error { return errHook }); !errors.Is(err, errHook) {
		t.Errorf("do error = %v, want %v", err, errHook)
	}
}

func TestStaleFrameFromGoroutine(t *testing.T) {
	tests := map[string]struct {
		panics bool
	}{
		"error: test builds panic":                 {panics: true},
		"error: other builds return ErrStaleFrame": {panics: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			saved := panicOnStaleFrame
			panicOnStaleFrame = tt.panics
			t.Cleanup(func() { panicOnStaleFrame = saved })

			d := &dispatcher{}
			released := make(chan struct{})
			type outcome struct {
				recovered any
				err       error
			}
			result := make(chan outcome, 1)
			var wg sync.WaitGroup

			err := d.do(t.Context(), func(ctx context.Context) error {
				// A goroutine started inside the hook keeps the hook's
				// context and uses it after the hook has returned.
				wg.Go(func() {
					<-released
					var o outcome
					o.recovered = capturePanic(func() {
						o.err = d.do(ctx, func(context.Context) error {
							t.Error("a stale frame was allowed to run under the dispatch lock")
							return nil
						})
					})
					result <- o
				})
				return nil
			})
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			close(released)
			within(t, "stale-frame goroutine", wg.Wait)

			o := <-result
			if tt.panics {
				perr, ok := o.recovered.(error)
				if !ok || !errors.Is(perr, ErrStaleFrame) {
					t.Fatalf("recovered %v, want a panic with ErrStaleFrame", o.recovered)
				}
				return
			}
			if o.recovered != nil {
				t.Fatalf("panicked with %v, want an error", o.recovered)
			}
			if !errors.Is(o.err, ErrStaleFrame) {
				t.Fatalf("do error = %v, want ErrStaleFrame", o.err)
			}
		})
	}
}

func TestFrameOfAnotherDispatcherIsIgnored(t *testing.T) {
	d1, d2 := &dispatcher{}, &dispatcher{}
	within(t, "nested dispatchers", func() {
		err := d1.do(t.Context(), func(ctx context.Context) error {
			return d2.do(ctx, func(ctx context.Context) error {
				f := frameFrom(ctx)
				if f.d != d2 || f.depth != 1 {
					t.Errorf("frame = {dispatcher %p, depth %d}, want {%p, 1}", f.d, f.depth, d2)
				}
				return nil
			})
		})
		if err != nil {
			t.Errorf("do: %v", err)
		}
	})
}

func TestConcurrentLetsOtherHooksRun(t *testing.T) {
	d, starts, ends := countingDispatcher()
	inBody := make(chan struct{})
	otherRan := make(chan struct{})
	var wg sync.WaitGroup

	// Flow A blocks inside Concurrent until flow B's hook has run, which
	// can only happen if the lock was released around the body.
	wg.Go(func() {
		err := d.do(t.Context(), func(ctx context.Context) error {
			ctx, err := Concurrent(ctx, func(ctx context.Context) error {
				if frameFrom(ctx) != nil {
					t.Error("the Concurrent body received a dispatch frame")
				}
				close(inBody)
				<-otherRan
				return nil
			})
			if err != nil {
				return err
			}
			// The fresh frame works for the rest of the hook.
			return d.do(ctx, func(ctx context.Context) error {
				if got := frameFrom(ctx).depth; got != 2 {
					t.Errorf("re-entry after Concurrent at depth %d, want 2", got)
				}
				return nil
			})
		})
		if err != nil {
			t.Errorf("flow A: %v", err)
		}
	})

	within(t, "flow B's hook while flow A is in Concurrent", func() {
		<-inBody
		err := d.do(t.Context(), func(context.Context) error {
			close(otherRan)
			return nil
		})
		if err != nil {
			t.Errorf("flow B: %v", err)
		}
	})
	within(t, "flow A", wg.Wait)

	// A: acquire, release for the body, reacquire, release. B: one hold.
	if *starts != 3 || *ends != 3 {
		t.Errorf("lock acquired %d times and released %d times, want 3 each", *starts, *ends)
	}
}

func TestConcurrentRefreshesFrame(t *testing.T) {
	d := &dispatcher{}
	within(t, "Concurrent", func() {
		err := d.do(t.Context(), func(ctx context.Context) error {
			outer := frameFrom(ctx)
			if d.current(outer) != outer {
				t.Error("current() of the outermost frame is not the frame of the hold")
			}
			nctx, err := Concurrent(ctx, func(context.Context) error { return nil })
			if err != nil {
				return err
			}
			fresh := frameFrom(nctx)
			if fresh == outer || fresh.depth != 1 {
				t.Errorf("Concurrent returned frame %+v, want a new outermost frame", fresh)
			}
			if d.current(outer) != fresh {
				t.Error("current() does not return the frame issued after Concurrent")
			}

			// The context from before Concurrent is stale for good.
			r := capturePanic(func() { _ = d.do(ctx, func(context.Context) error { return nil }) })
			if perr, ok := r.(error); !ok || !errors.Is(perr, ErrStaleFrame) {
				t.Errorf("using the pre-Concurrent context recovered %v, want ErrStaleFrame", r)
			}
			return nil
		})
		if err != nil {
			t.Errorf("do: %v", err)
		}
	})
}

func TestConcurrentReturnsBodyError(t *testing.T) {
	d := &dispatcher{}
	errBody := errors.New("body failed")
	within(t, "Concurrent", func() {
		err := d.do(t.Context(), func(ctx context.Context) error {
			nctx, err := Concurrent(ctx, func(context.Context) error { return errBody })
			if !errors.Is(err, errBody) {
				t.Errorf("Concurrent error = %v, want %v", err, errBody)
			}
			// The lock is held again even though the body failed.
			return d.do(nctx, func(context.Context) error { return nil })
		})
		if err != nil {
			t.Errorf("do: %v", err)
		}
	})
}

func TestConcurrentRefused(t *testing.T) {
	tests := map[string]struct {
		run     func(t *testing.T, d *dispatcher, body func(context.Context) error) error
		wantErr error
		wantMsg string
	}{
		"error: nested dispatch": {
			run: func(t *testing.T, d *dispatcher, body func(context.Context) error) error {
				var cerr error
				err := d.do(t.Context(), func(ctx context.Context) error {
					return d.do(ctx, func(ctx context.Context) error {
						_, cerr = Concurrent(ctx, body)
						// The frame stays valid after the refusal.
						return d.do(ctx, func(context.Context) error { return nil })
					})
				})
				if err != nil {
					t.Errorf("do: %v", err)
				}
				return cerr
			},
			wantErr: ErrSyncContext,
			wantMsg: "cannot be called from sync context",
		},
		"error: outside a hook": {
			run: func(t *testing.T, d *dispatcher, body func(context.Context) error) error {
				_, err := Concurrent(t.Context(), body)
				return err
			},
			wantErr: ErrNoDispatch,
		},
		"error: nil context": {
			run: func(t *testing.T, d *dispatcher, body func(context.Context) error) error {
				_, err := Concurrent(nil, body) //nolint:staticcheck // A nil context must be refused, not dereferenced.
				return err
			},
			wantErr: ErrNoDispatch,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d := &dispatcher{}
			ran := false
			var err error
			within(t, "Concurrent", func() {
				err = tt.run(t, d, func(context.Context) error { ran = true; return nil })
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Concurrent error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("Concurrent error %q does not contain %q", err, tt.wantMsg)
			}
			if ran {
				t.Error("the body of a refused Concurrent ran")
			}
		})
	}
}

func TestConcurrentWithStaleFrame(t *testing.T) {
	d := &dispatcher{}
	var hctx context.Context
	if err := d.do(t.Context(), func(ctx context.Context) error { hctx = ctx; return nil }); err != nil {
		t.Fatalf("do: %v", err)
	}
	r := capturePanic(func() { _, _ = Concurrent(hctx, func(context.Context) error { return nil }) })
	if perr, ok := r.(error); !ok || !errors.Is(perr, ErrStaleFrame) {
		t.Errorf("Concurrent with a stale frame recovered %v, want ErrStaleFrame", r)
	}
}

func TestPanicReleasesLock(t *testing.T) {
	tests := map[string]struct {
		hook func(ctx context.Context) error
	}{
		"error: hook panics": {
			hook: func(context.Context) error { panic("addon bug") },
		},
		"error: Concurrent body panics": {
			hook: func(ctx context.Context) error {
				_, err := Concurrent(ctx, func(context.Context) error { panic("addon bug") })
				return err
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d, starts, ends := countingDispatcher()
			within(t, "panicking hook", func() {
				if r := capturePanic(func() { _ = d.do(t.Context(), tt.hook) }); r != "addon bug" {
					t.Errorf("recovered %v, want the hook's panic", r)
				}
			})
			within(t, "dispatch after a panic", func() {
				if err := d.do(t.Context(), func(context.Context) error { return nil }); err != nil {
					t.Errorf("do: %v", err)
				}
			})
			if *starts != *ends {
				t.Errorf("lock acquired %d times but released %d times", *starts, *ends)
			}
		})
	}
}

// TestLiveFrameFromGoroutineIsNotDetected pins the limit the package
// documentation states: a goroutine started by a hook that uses the hook's
// frame while the hook still holds the lock re-enters without being
// refused, because a frame is valid for its whole hold of the lock and Go
// has no goroutine identity to check. The hook waits for the goroutine, so
// the two never run at the same time here; the test only shows that
// nothing stops the use. If this test starts failing, the documented limit
// is gone and the package documentation must say so.
func TestLiveFrameFromGoroutineIsNotDetected(t *testing.T) {
	d, starts, ends := countingDispatcher()
	var (
		inner error
		ran   bool
	)
	within(t, "hook with a goroutine", func() {
		err := d.do(t.Context(), func(ctx context.Context) error {
			done := make(chan struct{})
			go func() {
				defer close(done)
				inner = d.do(ctx, func(context.Context) error { ran = true; return nil })
			}()
			<-done
			return nil
		})
		if err != nil {
			t.Errorf("do: %v", err)
		}
	})
	if inner != nil || !ran {
		t.Errorf("the goroutine's do = %v, ran = %v; want it to re-enter undetected", inner, ran)
	}
	if *starts != 1 || *ends != 1 {
		t.Errorf("lock acquired %d and released %d times, want 1 and 1: the goroutine re-entered the hook's hold", *starts, *ends)
	}
}
