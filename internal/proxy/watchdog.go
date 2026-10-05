// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type watchdogTimer interface {
	Stop() bool
}

// afterFunc schedules f without invoking it synchronously.
type watchdogClock interface {
	now() time.Time
	afterFunc(time.Duration, func()) watchdogTimer
}

type wallClock struct{}

func (wallClock) now() time.Time                                    { return time.Now() }
func (wallClock) afterFunc(d time.Duration, f func()) watchdogTimer { return time.AfterFunc(d, f) }

// watchdog measures idle time outside hooks and interception waits, like
// TimeoutWatchdog in mitmproxy/proxy/server.py. Its callbacks never run with
// mu held, so expiry may cancel the connection and stop the watchdog.
type watchdog struct {
	mu         sync.Mutex
	clock      watchdogClock
	timeout    time.Duration
	deadline   time.Time
	timer      watchdogTimer
	generation uint64
	blockers   int
	closed     bool
	expire     func()
}

func newWatchdog(timeout time.Duration, clock watchdogClock, expire func()) *watchdog {
	if clock == nil {
		clock = wallClock{}
	}
	w := &watchdog{clock: clock, timeout: timeout, expire: expire}
	w.mu.Lock()
	w.deadline = clock.now().Add(timeout)
	w.scheduleLocked(timeout)
	w.mu.Unlock()
	return w
}

func (w *watchdog) scheduleLocked(delay time.Duration) {
	w.generation++
	generation := w.generation
	w.timer = w.clock.afterFunc(delay, func() {
		w.mu.Lock()
		if w.closed || w.blockers != 0 || generation != w.generation {
			w.mu.Unlock()
			return
		}
		if remaining := w.deadline.Sub(w.clock.now()); remaining > 0 {
			w.scheduleLocked(remaining)
			w.mu.Unlock()
			return
		}
		w.closed = true
		w.timer = nil
		w.mu.Unlock()
		w.expire()
	})
}

func (w *watchdog) activity() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed && w.blockers == 0 {
		// Moving only the deadline avoids allocating a timer per I/O.
		w.deadline = w.clock.now().Add(w.timeout)
	}
}

func (w *watchdog) disarm() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.blockers++
	if w.blockers == 1 {
		w.generation++
		w.timer.Stop()
		w.timer = nil
	}
}

func (w *watchdog) rearm() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	if w.blockers == 0 {
		panic("proxy: rearming a watchdog that was not disarmed")
	}
	w.blockers--
	if w.blockers == 0 {
		w.deadline = w.clock.now().Add(w.timeout)
		w.scheduleLocked(w.timeout)
	}
}

func (w *watchdog) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	w.generation++
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
}

// activityConn wraps the raw transport before recording, so replaying sniffed
// bytes does not incorrectly count as new network activity.
type activityConn struct {
	layer.Conn
	watchdog *watchdog
}

func (c *activityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.watchdog.activity()
	}
	return n, err
}

func (c *activityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.watchdog.activity()
	}
	return n, err
}
