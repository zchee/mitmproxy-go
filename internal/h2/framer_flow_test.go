// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

type malformedFrameFlowObserver struct {
	head  chan struct{}
	error chan string
}

// Name identifies the flow diagnostic observer.
func (*malformedFrameFlowObserver) Name() string { return "malformed-frame-flow" }

// RequestHeaders confirms the stream exists before the malformed frame is sent.
func (o *malformedFrameFlowObserver) RequestHeaders(_ context.Context, f *flow.HTTPFlow) error {
	if f.Request.Path == "/broken" {
		o.head <- struct{}{}
	}
	return nil
}

// Error snapshots the actual flow error under the addon dispatch lock.
func (o *malformedFrameFlowObserver) Error(_ context.Context, f *flow.HTTPFlow) error {
	if f.Request != nil && f.Request.Path == "/broken" {
		message := "missing flow error"
		if f.Error != nil {
			message = f.Error.Msg
		}
		o.error <- message
	}
	return nil
}

// TestMalformedPresentFramerFlow is a behavioural regression through the real
// Handler, HTTP adapter and flow hooks. The parent records reset-by-peer text.
func TestMalformedPresentFramerFlow(t *testing.T) {
	tests := map[string]struct{ increment uint32 }{
		"error: zero window update on an open stream": {},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			observer := &malformedFrameFlowObserver{head: make(chan struct{}, 1), error: make(chan string, 1)}
			origin := proxytest.StartHTTPOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/healthy" {
					t.Errorf("unexpected origin request: %s", r.URL.Path)
				}
				_, _ = io.WriteString(w, "healthy")
			}))
			proxy := proxytest.Start(t, proxytest.WithOrigin("origin.test", origin), proxytest.WithAddons(observer), proxytest.WithOptions(map[string]any{"http2": true, "connection_strategy": "lazy"}))
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			conn, err := new(net.Dialer).DialContext(ctx, "tcp", proxy.Addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			deadline, _ := ctx.Deadline()
			if err := conn.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
				t.Fatal(err)
			}
			framer := http2.NewFramer(conn, conn)
			if err := framer.WriteSettings(); err != nil {
				t.Fatal(err)
			}
			for {
				frame, err := framer.ReadFrame()
				if err != nil {
					t.Fatal(err)
				}
				if settings, ok := frame.(*http2.SettingsFrame); ok {
					if settings.IsAck() {
						break
					}
					if err := framer.WriteSettingsAck(); err != nil {
						t.Fatal(err)
					}
				}
			}
			writeMalformedFlowHeaders(t, framer, 1, "/broken", false)
			select {
			case <-observer.head:
			case <-ctx.Done():
				t.Fatal("request headers were not admitted before malformed frame")
			}
			framer.AllowIllegalWrites = true
			if err := framer.WriteWindowUpdate(1, test.increment); err != nil {
				t.Fatal(err)
			}
			for {
				frame, err := framer.ReadFrame()
				if err != nil {
					t.Fatal(err)
				}
				if reset, ok := frame.(*http2.RSTStreamFrame); ok && reset.StreamID == 1 {
					if reset.ErrCode != http2.ErrCodeProtocol {
						t.Fatalf("malformed frame reset = %v, want PROTOCOL_ERROR", reset.ErrCode)
					}
					break
				}
				if _, connectionClosed := frame.(*http2.GoAwayFrame); connectionClosed {
					t.Fatal("present-stream framer error closed the connection")
				}
			}
			var message string
			select {
			case message = <-observer.error:
			case <-ctx.Done():
				t.Fatal("malformed frame did not reach the flow error hook")
			}
			const want = "malformed HTTP/2 frame: stream error: stream ID 1; PROTOCOL_ERROR"
			if diff := gocmp.Diff(want, message); diff != "" {
				t.Fatalf("flow error (-want +got):\n%s", diff)
			}
			writeMalformedFlowHeaders(t, framer, 3, "/healthy", true)
			var body bytes.Buffer
			for {
				frame, err := framer.ReadFrame()
				if err != nil {
					t.Fatal(err)
				}
				switch frame := frame.(type) {
				case *http2.DataFrame:
					if frame.StreamID == 3 {
						body.Write(frame.Data())
						if frame.StreamEnded() {
							if diff := gocmp.Diff("healthy", body.String()); diff != "" {
								t.Fatalf("sibling body (-want +got):\n%s", diff)
							}
							return
						}
					}
				case *http2.RSTStreamFrame:
					if frame.StreamID == 3 {
						t.Fatalf("sibling reset = %v", frame.ErrCode)
					}
				case *http2.GoAwayFrame:
					t.Fatalf("sibling connection failed = %v", frame.ErrCode)
				}
			}
		})
	}
}

func writeMalformedFlowHeaders(t *testing.T, framer *http2.Framer, id uint32, path string, end bool) {
	t.Helper()
	var buffer bytes.Buffer
	encoder := hpack.NewEncoder(&buffer)
	fields := []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "origin.test"}, {Name: ":path", Value: path}}
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: id, EndHeaders: true, EndStream: end, BlockFragment: buffer.Bytes()}); err != nil {
		t.Fatal(err)
	}
}
