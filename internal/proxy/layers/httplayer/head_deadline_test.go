// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

type headTestTimer struct {
	at       time.Time
	callback func()
	active   bool
}

type headTestClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*headTestTimer
	armed  chan struct{}
}

func (c *headTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *headTestClock) AfterFunc(d time.Duration, callback func()) func() bool {
	c.mu.Lock()
	timer := &headTestTimer{at: c.now.Add(d), callback: callback, active: true}
	c.timers = append(c.timers, timer)
	c.mu.Unlock()
	if c.armed != nil {
		c.armed <- struct{}{}
	}
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		active := timer.active
		timer.active = false
		return active
	}
}

func (c *headTestClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var ready []func()
	for _, timer := range c.timers {
		if timer.active && !timer.at.After(c.now) {
			timer.active = false
			ready = append(ready, timer.callback)
		}
	}
	c.mu.Unlock()
	for _, callback := range ready {
		callback()
	}
}

func (c *headTestClock) counts() (scheduled, active int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, timer := range c.timers {
		if timer.active {
			active++
		}
	}
	return len(c.timers), active
}

type headObservedConn struct {
	layer.Conn
	started chan struct{}
	read    chan int
	once    sync.Once
}

func (c *headObservedConn) Read(b []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	n, err := c.Conn.Read(b)
	select {
	case c.read <- n:
	default:
	}
	return n, err
}

func TestHTTP1HeadDeadline(t *testing.T) {
	tests := map[string]struct {
		response  bool
		keepalive bool
		action    string
	}{
		"error: initial silent request expires":                      {action: "silent"},
		"error: trickled keepalive request head expires":             {keepalive: true, action: "expire"},
		"error: idle keepalive cancellation schedules no head timer": {keepalive: true, action: "idle cancel"},
		"error: origin wait cancellation schedules no head timer":    {response: true, action: "idle cancel"},
		"error: trickled request head expires":                       {action: "expire"},
		"error: trickled response head expires":                      {response: true, action: "expire"},
		"error: cancelled request stops timer":                       {action: "cancel"},
		"error: cancelled response stops timer":                      {response: true, action: "cancel"},
		"error: disconnected request stops timer":                    {action: "close"},
		"error: disconnected response stops timer":                   {response: true, action: "close"},
		"success: request body outlives head timer":                  {action: "complete"},
		"success: response body outlives head timer":                 {response: true, action: "complete"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			conn, peer := layertest.Pipe(t)
			clock := &headTestClock{armed: make(chan struct{}, 8)}
			observed := &headObservedConn{Conn: conn, started: make(chan struct{}), read: make(chan int, 16)}
			ctx, cancel := context.WithCancel(t.Context())
			var workers sync.WaitGroup
			t.Cleanup(func() {
				cancel()
				_ = conn.Close()
				workers.Wait()
			})
			wire := newWireStore()
			var receive func(context.Context) (Event, error)
			prefix := "POST / HTTP/1.1\r\nHost: localhost\r\n"
			if tt.response {
				endpoint := newHTTP1Client(observed, wire, nil)
				endpoint.clock = clock
				endpoint.id, endpoint.bound = 1, true
				endpoint.request = &httpmsg.Request{Method: "GET"}
				receive = func(ctx context.Context) (Event, error) { return endpoint.Receive(ctx) }
				prefix = "HTTP/1.1 200 OK\r\n"
			} else {
				endpoint := newHTTP1Server(observed, wire, nil)
				endpoint.clock = clock
				if tt.keepalive {
					endpoint.id = 3
				}
				receive = func(ctx context.Context) (Event, error) { return endpoint.Receive(ctx) }
			}
			type result struct {
				event Event
				err   error
			}
			done := make(chan result, 1)
			start := func() {
				workers.Go(func() {
					event, err := receive(ctx)
					done <- result{event, err}
				})
			}
			start()
			await(t, observed.started)
			if tt.response || tt.keepalive {
				clock.advance(2 * layer.HeadReadTimeout)
				if scheduled, active := clock.counts(); scheduled != 0 || active != 0 {
					t.Fatalf("idle read timer scheduled=%d active=%d, want 0 and 0", scheduled, active)
				}
				if tt.action == "idle cancel" {
					cancel()
					if got := await(t, done); !errors.Is(got.err, context.Canceled) {
						t.Fatalf("idle read error = %v, want context.Canceled", got.err)
					}
					return
				}
			} else if scheduled, active := clock.counts(); scheduled != 1 || active != 1 {
				t.Fatalf("initial head timer scheduled=%d active=%d, want 1 and 1", scheduled, active)
			}
			if tt.action == "silent" {
				clock.advance(layer.HeadReadTimeout)
				if got := await(t, done); !errors.Is(got.err, context.DeadlineExceeded) {
					t.Fatalf("silent read error = %v, want context.DeadlineExceeded", got.err)
				}
				return
			}
			writeAll(t, peer, prefix)
			await(t, observed.read)
			await(t, clock.armed)
			clock.advance(layer.HeadReadTimeout / 2)
			writeAll(t, peer, "Content-Length: 1\r\n")
			await(t, observed.read)
			var wantErr error
			switch tt.action {
			case "expire":
				clock.advance(layer.HeadReadTimeout / 2)
				wantErr = context.DeadlineExceeded
			case "cancel":
				cancel()
				wantErr = context.Canceled
			case "close":
				if err := peer.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			case "complete":
				writeAll(t, peer, "\r\n")
			}
			got := await(t, done)
			if tt.action == "close" {
				if got.err == nil && got.event == nil {
					t.Fatal("peer closure produced neither an error nor a protocol event")
				}
			} else if !errors.Is(got.err, wantErr) {
				t.Fatalf("Receive() error = %v, want %v", got.err, wantErr)
			}
			if scheduled, active := clock.counts(); scheduled != 1 || active != 0 {
				t.Fatalf("finished head timer scheduled=%d active=%d, want 1 and 0", scheduled, active)
			}
			clock.advance(layer.HeadReadTimeout)
			if tt.action == "complete" {
				start()
				writeAll(t, peer, "b")
				body := await(t, done)
				if body.err != nil {
					t.Fatalf("body read after head timeout: %v", body.err)
				}
				if diff := gocmp.Diff("b", summarize(body.event).Data); diff != "" {
					t.Fatalf("body (-want +got):\n%s", diff)
				}
			} else if tt.action != "close" {
				// An expired callback must not leave the transport deadline set.
				fresh := make(chan error, 1)
				workers.Go(func() {
					var b [1]byte
					_, err := io.ReadFull(conn, b[:])
					fresh <- err
				})
				writeAll(t, peer, "b")
				if err := await(t, fresh); err != nil {
					t.Fatalf("fresh read inherited head deadline: %v", err)
				}
			}
		})
	}
}

func TestHTTPLayerHeadClock(t *testing.T) {
	tests := map[string]struct {
		response bool
		status   string
	}{
		"error: silent initial request closes client":   {},
		"error: incomplete origin head closes exchange": {response: true, status: "HTTP/1.1 502 "},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newLayerSession(t, nil, "connection_strategy=lazy")
			clock := &headTestClock{armed: make(chan struct{}, 8)}
			s.c.Clock = clock
			s.start(hookdata.HTTPModeRegular)
			await(t, clock.armed)
			if tt.response {
				write(t, s.client, "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				origin := await(t, s.pool.origins)
				expectRead(t, origin, "GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				write(t, origin, "HTTP/1.1 200 OK\r\n")
				await(t, clock.armed)
			}
			clock.advance(layer.HeadReadTimeout)
			response := readToEOF(t, s.client)
			if tt.status == "" && response != "" || tt.status != "" && !strings.HasPrefix(response, tt.status) {
				t.Fatalf("timeout response = %q, want status prefix %q", response, tt.status)
			}
			if err := await(t, s.done); err != nil {
				t.Fatalf("layer after timeout: %v", err)
			}
			if _, active := clock.counts(); active != 0 {
				t.Fatalf("layer retained %d head timers after retirement", active)
			}
		})
	}
}
