// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
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

type observingConn struct {
	net.Conn
	writes chan struct{}
}

func (c *observingConn) Write(data []byte) (int, error) {
	c.writes <- struct{}{}
	return c.Conn.Write(data)
}

func TestUnresponsivePeerShutdown(t *testing.T) {
	tests := map[string]struct {
		shutdown bool
		blocked  bool
	}{
		"error: head deadline interrupts blocked preface": {blocked: true},
		"error: head deadline bounds GOAWAY flush":        {},
		"error: shutdown interrupts blocked DATA":         {shutdown: true, blocked: true},
		"error: shutdown bounds GOAWAY flush":             {shutdown: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			clock := &testClock{now: time.Unix(0, 0), scheduled: make(chan struct{}, 16)}
			conn, peer := net.Pipe()
			observed := &observingConn{Conn: conn, writes: make(chan struct{}, 32)}
			e, err := New(observed, Config{Client: true, Clock: clock, Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			go func() { _ = e.Run(ctx) }()
			t.Cleanup(func() { cancel(); _ = conn.Close(); _ = peer.Close(); <-e.Done() })
			<-clock.scheduled
			if test.blocked && !test.shutdown {
				<-observed.writes
				clock.advance(layer.HeadReadTimeout)
			} else {
				preface := make([]byte, len(http2.ClientPreface))
				if _, err := io.ReadFull(peer, preface); err != nil {
					t.Fatal(err)
				}
				fr := http2.NewFramer(peer, peer)
				for range 2 {
					if _, err := fr.ReadFrame(); err != nil {
						t.Fatal(err)
					}
				}
				if err := fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: InitialStreamWindow}); err != nil {
					t.Fatal(err)
				}
				if _, err := fr.ReadFrame(); err != nil {
					t.Fatal(err)
				}
				id, err := e.OpenStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				sent := make(chan error, 1)
				go func() { sent <- e.Send(ctx, Event{Kind: Headers, Identity: id, Headers: requestFields()}) }()
				if _, err := fr.ReadFrame(); err != nil {
					t.Fatal(err)
				}
				if err := <-sent; err != nil {
					t.Fatal(err)
				}
				for range 5 {
					<-observed.writes
				}
				if test.shutdown {
					if test.blocked {
						go func() { sent <- e.Send(ctx, Event{Kind: Data, Identity: id, Data: []byte("blocked")}) }()
						<-observed.writes
					}
					go func() { _ = e.Shutdown(ctx, http2.ErrCodeNo, nil) }()
				} else {
					if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id.Stream, BlockFragment: []byte{0x88}}); err != nil {
						t.Fatal(err)
					}
					<-clock.scheduled
					clock.advance(layer.HeadReadTimeout)
				}
				if !test.blocked {
					<-clock.scheduled
					<-observed.writes
					clock.advance(GoAwayFlushGrace)
				}
			}
			select {
			case <-e.Done():
			case <-ctx.Done():
				buf := make([]byte, 1<<20)
				n := runtime.Stack(buf, true)
				t.Fatalf("unresponsive peer cleanup hung:\n%s", buf[:n])
			}
			protocol, ok := errors.AsType[*ProtocolError](e.endError())
			if !ok || !protocol.Timeout() {
				t.Fatalf("unresponsive peer error = %v", e.endError())
			}
			if got := e.Budget(); got.Granted != 0 {
				t.Fatalf("unresponsive peer reservation = %+v", got)
			}
		})
	}
}

func TestKeepaliveStopsAfterDisconnect(t *testing.T) {
	clock := &testClock{now: time.Unix(0, 0)}
	p := newPipePeer(t, Config{Client: true, Clock: clock, PingKeepalive: time.Minute})
	p.settings(t)
	if err := p.conn.Close(); err != nil {
		t.Fatal(err)
	}
	<-p.endpoint.Done()
	clock.advance(10 * time.Minute)
	clock.mu.Lock()
	defer clock.mu.Unlock()
	for _, timer := range clock.timers {
		if !timer.stopped {
			t.Fatal("timer survived connection shutdown")
		}
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
			var wire wireFrame
			if test.headers {
				wire = p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameGoAway })
			} else {
				// Initial SETTINGS may still be in flight when the preface expires.
				// An active writer is interrupted rather than delaying the timeout.
				for frame := range p.frames {
					if frame.kind == http2.FrameGoAway {
						wire = frame
						break
					}
				}
			}
			if wire.kind == http2.FrameGoAway && (wire.code != http2.ErrCodeProtocol || !bytes.Contains(wire.data, []byte("deadline exceeded"))) {
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
