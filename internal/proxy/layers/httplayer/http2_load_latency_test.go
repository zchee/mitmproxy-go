// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build h2load

package httplayer

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/zchee/mitmproxy-go/flow"
)

type loadIntercept struct{ paused chan struct{} }

func (a *loadIntercept) RequestHeaders(_ context.Context, f *flow.HTTPFlow) error {
	if f.Request.Path == "/paused" {
		f.Intercept()
		a.paused <- struct{}{}
	}
	return nil
}

func TestHTTP2LoadUnrelatedResponse(t *testing.T) {
	tests := map[string]struct{ stoppedTCP bool }{"success: intercepted stream does not hold sibling": {}, "success: stopped TCP reader is separately bounded and cancellable": {stoppedTCP: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			interceptor := &loadIntercept{paused: make(chan struct{}, 1)}
			var addon any = interceptor
			if tt.stoppedTCP {
				addon = nil
			}
			s := newLoadHTTP2Session(t, 128<<10, addon, 30*time.Second)
			if tt.stoppedTCP {
				if err := s.client.conn.(*net.TCPConn).SetReadBuffer(16 << 10); err != nil {
					t.Fatal(err)
				}
				if err := s.client.write(func(f *http2.Framer) error {
					return f.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 16 << 20})
				}); err != nil {
					t.Fatal(err)
				}
				s.client.mu.Lock()
				s.client.paused = true
				s.client.mu.Unlock()
				if err := s.request(3, "GET", "/stalled", true); err != nil {
					t.Fatal(err)
				}
				_ = await(t, s.client.stopped)
				endpoint := s.view.endpoint(t)
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				for endpoint.Budget().Granted == 0 {
					select {
					case <-ticker.C:
					case <-s.ctx.Done():
						t.Fatal(s.ctx.Err())
					}
				}
				budget := endpoint.Budget()
				if budget.Maximum > 128<<20 {
					t.Fatalf("stopped-reader receive budget = %+v", budget)
				}
				s.cancel()
				_ = await(t, endpoint.Done())
				if got := endpoint.Budget().Granted; got != 0 {
					t.Errorf("receive grants after stopped-reader cancellation = %d", got)
				}
				t.Logf("stopped TCP reader: peak receive grant=%d, cancellation released all grants", budget.Maximum)
				return
			}
			s.client.mu.Lock()
			s.client.withholdAfter = 1
			s.client.withholdExcept = 5
			s.client.mu.Unlock()
			if err := s.request(3, "POST", "/paused", false); err != nil {
				t.Fatal(err)
			}
			_ = await(t, interceptor.paused)
			s.client.workers.Go(func() { _ = s.client.body(3, make([]byte, 128<<10), loadBodySize) })
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				s.client.mu.Lock()
				credit, changed := s.client.streamCredit[3], s.client.creditChanged
				s.client.mu.Unlock()
				if credit == 0 {
					break
				}
				select {
				case <-changed:
				case <-ticker.C:
				case <-s.ctx.Done():
					t.Fatal(s.ctx.Err())
				}
			}
			started := time.Now()
			if err := s.request(5, "GET", "/small", true); err != nil {
				t.Fatal(err)
			}
			if got := await(t, s.client.finished); got != 5 {
				t.Fatalf("unrelated completed stream = %d", got)
			}
			elapsed := time.Since(started)
			if got := s.client.bytes(5); got != 4<<20 {
				t.Errorf("unrelated response bytes = %d", got)
			}
			if elapsed > 2*time.Second {
				t.Errorf("isolated unrelated response duration = %s", elapsed)
			}
			t.Logf("intercepted sibling response: 4 MiB, duration=%s", elapsed)
		})
	}
}

func (*loadSSEStreaming) ResponseHeaders(_ context.Context, f *flow.HTTPFlow) error {
	if f.Request.Path == "/sse" {
		f.Response.Stream = true
	}
	return nil
}

type loadSSEStreaming struct{}

func TestHTTP2LoadSSELatency(t *testing.T) {
	tests := map[string]struct{ size int }{"success: 100-byte DATA is forwarded before the next emission": {size: 100}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newLoadHTTP2Session(t, 128<<10, &loadSSEStreaming{}, 30*time.Second)
			s.client.mu.Lock()
			s.client.noticeID = 3
			s.client.mu.Unlock()
			if err := s.request(3, "GET", "/sse", true); err != nil {
				t.Fatal(err)
			}
			for i := range 2 {
				emitted := await(t, s.origin.firstData)
				received := await(t, s.client.notices)
				latency := received.Sub(emitted)
				if got := s.client.bytes(3); got != int64((i+1)*tt.size) {
					t.Errorf("emission %d cumulative bytes = %d", i+1, got)
				}
				if latency > 100*time.Millisecond {
					t.Errorf("isolated DATA latency = %s", latency)
				}
				t.Logf("100-byte DATA emission %d with 500 ms emitter interval: forwarding latency=%s", i+1, latency)
			}
			if got := await(t, s.client.finished); got != 3 {
				t.Fatalf("completed SSE stream = %d", got)
			}
			if got := s.client.bytes(3); got != 2*int64(tt.size) {
				t.Errorf("complete SSE bytes = %d", got)
			}
		})
	}
}
