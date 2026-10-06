// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestPacketWatchdogBaseline(t *testing.T) {
	tests := map[string]struct {
		run func(*testing.T, *watchdog, *manualClock, *atomic.Int32)
	}{
		"expires at twenty seconds": {run: func(t *testing.T, w *watchdog, clock *manualClock, count *atomic.Int32) {
			clock.advance(20*time.Second - time.Nanosecond)
			requireExpirations(t, count, 0)
			clock.advance(time.Nanosecond)
			requireExpirations(t, count, 1)
		}},
		"datagram resets baseline": {run: func(t *testing.T, w *watchdog, clock *manualClock, count *atomic.Int32) {
			clock.advance(19 * time.Second)
			w.activity()
			clock.advance(time.Second)
			requireExpirations(t, count, 0)
			clock.advance(19 * time.Second)
			requireExpirations(t, count, 1)
		}},
		"short hook keeps datagram baseline": {run: func(t *testing.T, w *watchdog, clock *manualClock, count *atomic.Int32) {
			clock.advance(5 * time.Second)
			w.disarm()
			clock.advance(10 * time.Second)
			w.rearm()
			clock.advance(5 * time.Second)
			requireExpirations(t, count, 1)
		}},
		"overdue hook expires on rearm": {run: func(t *testing.T, w *watchdog, clock *manualClock, count *atomic.Int32) {
			w.disarm()
			clock.advance(time.Minute)
			requireExpirations(t, count, 0)
			w.rearm()
			clock.advance(0)
			requireExpirations(t, count, 1)
		}},
		"datagram during hook updates baseline": {run: func(t *testing.T, w *watchdog, clock *manualClock, count *atomic.Int32) {
			w.disarm()
			clock.advance(30 * time.Second)
			w.activity()
			clock.advance(5 * time.Second)
			w.rearm()
			clock.advance(14 * time.Second)
			requireExpirations(t, count, 0)
			clock.advance(time.Second)
			requireExpirations(t, count, 1)
		}},
		"nested hook rearms only after last return": {run: func(t *testing.T, w *watchdog, clock *manualClock, count *atomic.Int32) {
			w.disarm()
			w.disarm()
			clock.advance(time.Minute)
			w.rearm()
			clock.advance(0)
			requireExpirations(t, count, 0)
			w.rearm()
			clock.advance(0)
			requireExpirations(t, count, 1)
		}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			clock := new(manualClock)
			count := new(atomic.Int32)
			w := newPacketWatchdog(clock, func() { count.Add(1) })
			t.Cleanup(w.close)
			test.run(t, w, clock, count)
		})
	}
}
