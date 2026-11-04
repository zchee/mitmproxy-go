// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
)

type manualClock struct {
	mu      sync.Mutex
	current time.Time
	timers  []*manualTimer
}

type manualTimer struct {
	clock    *manualClock
	deadline time.Time
	callback func()
	active   bool
}

func (c *manualClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current
}

func (c *manualClock) afterFunc(d time.Duration, f func()) watchdogTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &manualTimer{clock: c, deadline: c.current.Add(d), callback: f, active: true}
	c.timers = append(c.timers, timer)
	return timer
}

func (t *manualTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	wasActive := t.active
	t.active = false
	return wasActive
}

func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	c.current = c.current.Add(d)
	var callbacks []func()
	for _, timer := range c.timers {
		if timer.active && !timer.deadline.After(c.current) {
			timer.active = false
			callbacks = append(callbacks, timer.callback)
		}
	}
	c.mu.Unlock()
	for _, callback := range callbacks {
		callback()
	}
}

func newTestWatchdog(t *testing.T, clock *manualClock) (*watchdog, *atomic.Int32) {
	t.Helper()
	calls := new(atomic.Int32)
	w := newWatchdog(5*time.Second, clock, func() { calls.Add(1) })
	t.Cleanup(w.close)
	return w, calls
}

func requireExpirations(t *testing.T, count *atomic.Int32, want int32) {
	t.Helper()
	if got := count.Load(); got != want {
		t.Fatalf("expiration count = %d, want %d", got, want)
	}
}

func TestWatchdogDeadline(t *testing.T) {
	tests := map[string]struct {
		run func(*testing.T, *watchdog, *manualClock, *atomic.Int32)
	}{
		"idle": {func(t *testing.T, _ *watchdog, clock *manualClock, count *atomic.Int32) {
			clock.advance(4 * time.Second)
			requireExpirations(t, count, 0)
			clock.advance(time.Second)
			requireExpirations(t, count, 1)
			clock.advance(time.Hour)
			requireExpirations(t, count, 1)
		}},
		"activity extends deadline without replacing timer": {func(t *testing.T, w *watchdog, clock *manualClock, count *atomic.Int32) {
			clock.advance(4 * time.Second)
			w.activity()
			if len(clock.timers) != 1 {
				t.Fatal("activity replaced the pending timer")
			}
			clock.advance(4 * time.Second)
			requireExpirations(t, count, 0)
			clock.advance(time.Second)
			requireExpirations(t, count, 1)
		}},
		"overlapping disarms": {func(t *testing.T, w *watchdog, clock *manualClock, count *atomic.Int32) {
			w.disarm()
			w.disarm()
			clock.advance(30 * time.Second)
			requireExpirations(t, count, 0)
			w.rearm()
			clock.advance(30 * time.Second)
			requireExpirations(t, count, 0)
			w.rearm()
			clock.advance(4 * time.Second)
			requireExpirations(t, count, 0)
			clock.advance(time.Second)
			requireExpirations(t, count, 1)
		}},
		"stale timer after rearm": {func(t *testing.T, w *watchdog, clock *manualClock, count *atomic.Int32) {
			oldCallback := clock.timers[0].callback
			w.disarm()
			clock.advance(30 * time.Second)
			w.rearm()
			oldCallback()
			requireExpirations(t, count, 0)
			clock.advance(5 * time.Second)
			requireExpirations(t, count, 1)
		}},
		"close suppresses queued callback": {func(t *testing.T, w *watchdog, clock *manualClock, count *atomic.Int32) {
			oldCallback := clock.timers[0].callback
			w.close()
			w.close()
			w.activity()
			w.disarm()
			w.rearm()
			clock.advance(time.Hour)
			oldCallback()
			requireExpirations(t, count, 0)
		}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			clock := new(manualClock)
			w, count := newTestWatchdog(t, clock)
			tt.run(t, w, clock, count)
		})
	}
}

func TestWatchdogHookExclusions(t *testing.T) {
	tests := map[string]struct{ intercepted bool }{
		"running hook":     {},
		"intercepted flow": {true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			clock := new(manualClock)
			w, count := newTestWatchdog(t, clock)
			_, idleCount := newTestWatchdog(t, clock)
			f := flow.NewHTTPFlow(nil, nil, true)
			entered := make(chan struct{})
			release := make(chan struct{}, 1)
			defer close(release)
			r := newHookRunner(t, &runnerAddon{request: func(context.Context, *flow.HTTPFlow) error {
				if tt.intercepted {
					f.Intercept()
				}
				close(entered)
				if !tt.intercepted {
					<-release
				}
				return nil
			}})
			r.Disarm, r.Rearm = w.disarm, w.rearm
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := r.Fire(ctx, addon.RequestHook{Flow: f}); done <- err }()
			await(t, entered)
			clock.advance(30 * time.Second)
			requireExpirations(t, count, 0)
			requireExpirations(t, idleCount, 1)
			if tt.intercepted {
				if err := r.Manager.Do(t.Context(), func(context.Context) error { f.Resume(); return nil }); err != nil {
					t.Fatal(err)
				}
			} else {
				release <- struct{}{}
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
			clock.advance(4 * time.Second)
			requireExpirations(t, count, 0)
			clock.advance(time.Second)
			requireExpirations(t, count, 1)
		})
	}
}

func TestWatchdogDispatchWaitExcluded(t *testing.T) {
	clock := new(manualClock)
	w, count := newTestWatchdog(t, clock)
	r := newHookRunner(t)
	locked, release := make(chan struct{}), make(chan struct{}, 1)
	defer close(release)
	hold := make(chan error, 1)
	go func() {
		hold <- r.Manager.Do(t.Context(), func(context.Context) error { close(locked); <-release; return nil })
	}()
	await(t, locked)
	disarmed := make(chan struct{})
	r.Disarm = func() { w.disarm(); close(disarmed) }
	r.Rearm = w.rearm
	done := make(chan error, 1)
	go func() { _, err := r.Fire(t.Context(), addon.RunningHook{}); done <- err }()
	await(t, disarmed)
	clock.advance(30 * time.Second)
	requireExpirations(t, count, 0)
	release <- struct{}{}
	if err := await(t, hold); err != nil {
		t.Fatal(err)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	clock.advance(5 * time.Second)
	requireExpirations(t, count, 1)
}

func TestWatchdogDefaultClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		expired := make(chan struct{})
		w := newWatchdog(5*time.Second, nil, func() { close(expired) })
		defer w.close()
		time.Sleep(4 * time.Second)
		select {
		case <-expired:
			t.Fatal("expired before idle deadline")
		default:
		}
		await(t, expired)
	})
}

func TestWatchdogConcurrentDisarms(t *testing.T) {
	clock := new(manualClock)
	w, count := newTestWatchdog(t, clock)
	w.disarm()
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			for range 100 {
				w.disarm()
				w.activity()
				clock.advance(time.Second)
				w.rearm()
			}
		})
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	await(t, done)
	requireExpirations(t, count, 0)
	w.rearm()
	clock.advance(5 * time.Second)
	requireExpirations(t, count, 1)
}

func TestWatchdogNonpositiveTimeout(t *testing.T) {
	tests := map[string]struct{ timeout time.Duration }{
		"zero":     {},
		"negative": {-time.Second},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			clock := new(manualClock)
			expired := false
			w := newWatchdog(tt.timeout, clock, func() { expired = true })
			defer w.close()
			clock.advance(0)
			if !expired {
				t.Fatal("nonpositive idle timeout did not expire")
			}
		})
	}
}

func TestWatchdogIOActivity(t *testing.T) {
	tests := map[string]struct{ write bool }{"read": {}, "write": {true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			clock := new(manualClock)
			w, count := newTestWatchdog(t, clock)
			a, b := net.Pipe()
			t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
			conn := &activityConn{Conn: memoryConn{Conn: a, input: a}, watchdog: w}
			clock.advance(4 * time.Second)
			done := make(chan error, 2)
			reader, writer := io.Reader(conn), io.Writer(b)
			if tt.write {
				reader, writer = b, conn
			}
			go func() { _, err := writer.Write([]byte("x")); done <- err }()
			go func() { _, err := io.ReadFull(reader, make([]byte, 1)); done <- err }()
			for range 2 {
				if err := await(t, done); err != nil {
					t.Fatal(err)
				}
			}
			clock.advance(4 * time.Second)
			requireExpirations(t, count, 0)
			clock.advance(time.Second)
			requireExpirations(t, count, 1)
		})
	}
}
