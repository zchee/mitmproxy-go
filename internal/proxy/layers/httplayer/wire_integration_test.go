// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
	"weak"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func finishLayerSession(t *testing.T, s *layerSession, hooks []string) {
	t.Helper()
	if err := s.client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := await(t, s.done); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(hooks, s.a.calls); diff != "" {
		t.Fatalf("hook order (-want +got):\n%s", diff)
	}
}

func TestLayerWireRoundTrips(t *testing.T) {
	tests := map[string]struct {
		request  string
		forward  string
		response string
		eof      bool
		pipeline bool
	}{
		"success: absolute target with query": {
			request:  "GET http://example.com/foo?hello=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			forward:  "GET /foo?hello=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			response: "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!",
		},
		"success: no headers": {
			request:  "GET http://example.com/ HTTP/1.1\r\n\r\n",
			forward:  "GET / HTTP/1.1\r\n\r\n",
			response: "HTTP/1.1 204 No Content\r\n\r\n",
		},
		"success: relative target": {
			request:  "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			forward:  "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			response: "HTTP/1.1 204 No Content\r\n\r\n",
		},
		"success: chunked HEAD has no terminal chunk": {
			request:  "HEAD http://example.com/ HTTP/1.1\r\n\r\n",
			forward:  "HEAD / HTTP/1.1\r\n\r\n",
			response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
		},
		"success: response ends at EOF": {
			request:  "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
			forward:  "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			response: "HTTP/1.1 200 OK\r\n\r\nfoo", eof: true,
		},
		"success: pipelined identity responses": {
			request:  "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
			forward:  "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			response: "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!", pipeline: true,
		},
		"success: pipelined chunked responses": {
			request:  "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
			forward:  "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nc\r\nHello World!\r\n0\r\n\r\n", pipeline: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newLayerSession(t, nil)
			s.start(hookdata.HTTPModeRegular)
			rounds := 1
			if tt.pipeline {
				rounds = 2
			}
			write(t, s.client, strings.Repeat(tt.request, rounds))
			origin := await(t, s.pool.origins)
			var hooks []string
			for range rounds {
				expectRead(t, origin, tt.forward)
				write(t, origin, tt.response)
				if tt.eof {
					if err := origin.CloseWrite(); err != nil {
						t.Fatal(err)
					}
				}
				expectRead(t, s.client, tt.response)
				hooks = append(hooks, "requestheaders", "request", "responseheaders", "response")
			}
			if tt.eof {
				if data, err := io.ReadAll(s.client); err != nil || len(data) != 0 {
					t.Fatalf("after response = (%q, %v), want EOF", data, err)
				}
			}
			finishLayerSession(t, s, hooks)
			if s.pool.openCount() != 1 {
				t.Fatal("round trips did not reuse the origin")
			}
		})
	}
}

func TestLayerRequestRejections(t *testing.T) {
	tests := map[string]struct {
		request, message string
		hooks            []string
	}{
		"error: relative target has no host": {"GET / HTTP/1.1\r\n\r\n", "HTTP request has no host header, destination unknown.", nil},
		"error: conflicting framing":         {"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42\r\nTransfer-Encoding: chunked\r\n\r\n", "Disable the validate_inbound_headers option to skip this security check", []string{"requestheaders", "error"}},
		"error: whitespace in header name":   {"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length : 42\r\n\r\n", "invalid header name", []string{"requestheaders", "error"}},
		"error: non-ASCII transfer encoding": {"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunKed\r\n\r\n", "invalid transfer-encoding header", []string{"requestheaders", "error"}},
		"error: nonnumeric content length":   {"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: NaN\r\n\r\n", "invalid content-length header", []string{"requestheaders", "error"}},
		"error: negative content length":     {"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: -1\r\n\r\n", "invalid content-length header", []string{"requestheaders", "error"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newLayerSession(t, nil)
			s.start(hookdata.HTTPModeRegular)
			write(t, s.client, tt.request)
			data, err := io.ReadAll(s.client)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(data, []byte("HTTP/1.1 400 ")) || !bytes.Contains(data, []byte(tt.message)) {
				t.Fatalf("rejection = %q, want 400 with %q", data, tt.message)
			}
			finishLayerSession(t, s, tt.hooks)
			if s.pool.openCount() != 0 {
				t.Fatal("rejected request opened an origin")
			}
		})
	}
}

func TestLayerFramingEdits(t *testing.T) {
	tests := map[string]struct{ addon bool }{
		"success: explicitly disabled inbound validation":      {},
		"success: addon sets chunked alongside content length": {addon: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				if !tt.addon {
					return
				}
				if name == "requestheaders" {
					f.Request.Headers.Set("Transfer-Encoding", "chunked")
				}
				if name == "response" {
					f.Response.Headers.Set("Transfer-Encoding", "chunked")
				}
			}}
			var specs []string
			if !tt.addon {
				specs = append(specs, "validate_inbound_headers=false")
			}
			s := newLayerSession(t, a, specs...)
			s.start(hookdata.HTTPModeRegular)
			if tt.addon {
				write(t, s.client, "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n")
			} else {
				write(t, s.client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n")
			}
			origin := await(t, s.pool.origins)
			if tt.addon {
				expectRead(t, origin, "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
			} else {
				expectRead(t, origin, "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n")
			}
			write(t, origin, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
			response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
			if tt.addon {
				response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
			}
			expectRead(t, s.client, response)
			finishLayerSession(t, s, []string{"requestheaders", "request", "responseheaders", "response"})
		})
	}
}

func TestLayerAbortedMessages(t *testing.T) {
	tests := map[string]struct {
		client, stream bool
		response       string
	}{
		"error: client aborts buffered body":          {client: true},
		"error: client aborts streamed body":          {client: true, stream: true},
		"error: server aborts buffered body":          {response: "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc"},
		"error: server aborts streamed body":          {stream: true, response: "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc"},
		"error: server sends no response":             {},
		"error: server sends incomplete invalid head": {response: "I don't speak HTTP."},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var observed *flow.HTTPFlow
			headers := make(chan struct{}, 1)
			a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				observed = f
				if name == "requestheaders" && tt.client {
					f.Request.Stream = tt.stream
					headers <- struct{}{}
				}
				if name == "responseheaders" {
					f.Response.Stream = tt.stream
				}
			}}
			s := newLayerSession(t, a)
			s.start(hookdata.HTTPModeRegular)
			wantHooks := []string{"requestheaders"}
			if tt.client {
				write(t, s.client, "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\n\r\nabc")
				await(t, headers)
				if tt.stream {
					origin := await(t, s.pool.origins)
					expectRead(t, origin, "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\n\r\nabc")
				}
				if err := s.client.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			} else {
				write(t, s.client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
				origin := await(t, s.pool.origins)
				expectRead(t, origin, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
				wantHooks = append(wantHooks, "request")
				if tt.response != "" {
					write(t, origin, tt.response)
				}
				if strings.HasPrefix(tt.response, "HTTP/") {
					wantHooks = append(wantHooks, "responseheaders")
				}
				if tt.stream {
					expectRead(t, s.client, tt.response)
				}
				if err := origin.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			data, err := io.ReadAll(s.client)
			if err != nil {
				t.Fatal(err)
			}
			if tt.client || tt.stream {
				if len(data) != 0 {
					t.Fatalf("aborted stream sent extra bytes: %q", data)
				}
			} else if !bytes.HasPrefix(data, []byte("HTTP/1.1 502 ")) {
				t.Fatalf("abort response = %q", data)
			}
			wantHooks = append(wantHooks, "error")
			if tt.client {
				if err := await(t, s.done); err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(wantHooks, s.a.calls); diff != "" {
					t.Fatalf("abort hooks (-want +got):\n%s", diff)
				}
			} else {
				finishLayerSession(t, s, wantHooks)
			}
			if observed == nil || observed.Error == nil || observed.Live {
				t.Fatalf("aborted flow = %+v", observed)
			}
			if (tt.client || strings.HasPrefix(tt.response, "HTTP/")) && !strings.Contains(observed.Error.Msg, "peer closed connection") {
				t.Fatalf("abort error = %q", observed.Error.Msg)
			}
		})
	}
}

func TestLayerReleasesFlows(t *testing.T) {
	tests := map[string]struct{ failed bool }{
		"success: completed flow is collectable during keepalive": {},
		"success: errored flow is collectable":                    {failed: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			flows := make(chan weak.Pointer[flow.HTTPFlow], 1)
			a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				if name == "requestheaders" {
					flows <- weak.Make(f)
				}
			}}
			s := newLayerSession(t, a)
			if tt.failed {
				s.pool.err = errors.New("connection failed")
			}
			s.start(hookdata.HTTPModeRegular)
			write(t, s.client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
			tracked := await(t, flows)
			if tt.failed {
				data, err := io.ReadAll(s.client)
				if err != nil || !bytes.Contains(data, []byte("connection failed")) {
					t.Fatalf("error response = (%q, %v)", data, err)
				}
				if err := await(t, s.done); err != nil {
					t.Fatal(err)
				}
			} else {
				origin := await(t, s.pool.origins)
				expectRead(t, origin, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
				write(t, origin, "HTTP/1.1 204 No Content\r\n\r\n")
				expectRead(t, s.client, "HTTP/1.1 204 No Content\r\n\r\n")
			}
			ctx, cancel := context.WithTimeout(t.Context(), layertest.Timeout)
			defer cancel()
			for tracked.Value() != nil {
				if err := ctx.Err(); err != nil {
					t.Fatalf("finished flow is still retained: %v", err)
				}
				runtime.GC()
				runtime.Gosched()
			}
			if !tt.failed {
				finishLayerSession(t, s, []string{"requestheaders", "request", "responseheaders", "response"})
			}
		})
	}
}

func TestLayerQueuedBodyAfterDialFailure(t *testing.T) {
	s := newLayerSession(t, nil, "stream_large_bodies=1")
	s.pool.err = errors.New("Connection killed: error")
	s.start(hookdata.HTTPModeRegular)
	write(t, s.client, "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ndata")
	data, err := io.ReadAll(s.client)
	if err != nil || !bytes.Contains(data, []byte("502 Bad Gateway")) || !bytes.Contains(data, []byte("Connection killed")) {
		t.Fatalf("queued-body failure = (%q, %v)", data, err)
	}
	finishLayerSession(t, s, []string{"requestheaders", "error"})
}
