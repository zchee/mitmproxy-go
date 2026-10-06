// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type clockTimer struct {
	at       time.Time
	callback func()
	stopped  bool
}
type testClock struct {
	mu        sync.Mutex
	now       time.Time
	timers    []*clockTimer
	scheduled chan struct{}
}

func (c *testClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testClock) AfterFunc(d time.Duration, callback func()) func() bool {
	c.mu.Lock()
	timer := &clockTimer{at: c.now.Add(d), callback: callback}
	c.timers = append(c.timers, timer)
	c.mu.Unlock()
	if c.scheduled != nil {
		c.scheduled <- struct{}{}
	}
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		if timer.stopped {
			return false
		}
		timer.stopped = true
		return true
	}
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var callbacks []func()
	for _, timer := range c.timers {
		if !timer.stopped && !timer.at.After(c.now) {
			timer.stopped = true
			callbacks = append(callbacks, timer.callback)
		}
	}
	c.mu.Unlock()
	for _, callback := range callbacks {
		callback()
	}
}

func TestHeadDeadlineAndKeepalive(t *testing.T) {
	tests := map[string]struct {
		headers bool
		ping    bool
	}{
		"error: first SETTINGS deadline":                       {},
		"error: trickled CONTINUATION does not reset deadline": {headers: true},
		"success: keepalive and unanswered ping repeat":        {ping: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			clock := &testClock{now: time.Unix(0, 0), scheduled: make(chan struct{}, 16)}
			cfg := Config{Client: true, Clock: clock}
			if test.ping {
				cfg.PingKeepalive = time.Minute
			}
			p := newPipePeer(t, cfg)
			// Observing the initial SETTINGS makes Run's timer registration visible.
			p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameSettings && !f.flags.Has(http2.FlagSettingsAck) })
			<-clock.scheduled
			if test.ping {
				p.settings(t)
				for range 2 {
					clock.advance(time.Minute)
					ping := p.frame(t, func(f wireFrame) bool { return f.kind == http2.FramePing })
					if string(ping.data) != "00000000" {
						t.Fatalf("PING = %q", ping.data)
					}
				}
				return
			}
			if test.headers {
				p.settings(t)
				id, err := p.endpoint.OpenStream(p.ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: id, Headers: requestFields()}); err != nil {
					t.Fatal(err)
				}
				if err := p.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: id.Stream, BlockFragment: []byte{0x88}}); err != nil {
					t.Fatal(err)
				}
				<-clock.scheduled
				clock.advance(layer.HeadReadTimeout / 2)
				if err := p.framer.WriteContinuation(id.Stream, false, nil); err != nil {
					t.Fatal(err)
				}
				clock.advance(layer.HeadReadTimeout / 2)
			} else {
				clock.advance(layer.HeadReadTimeout)
			}
			wire := p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameGoAway })
			if wire.code != http2.ErrCodeProtocol || !bytes.Contains(wire.data, []byte("deadline exceeded")) {
				t.Fatalf("deadline GOAWAY = %+v", wire)
			}
			<-p.endpoint.Done()
			err := p.endpoint.endError()
			protocol, ok := errors.AsType[*ProtocolError](err)
			if !ok || !protocol.Timeout() {
				t.Fatalf("deadline error = %v", err)
			}
		})
	}
}
