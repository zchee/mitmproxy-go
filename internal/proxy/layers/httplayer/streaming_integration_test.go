// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
)

func TestLayerRequestStreamingMatrix(t *testing.T) {
	tests := map[string]struct {
		chunked bool
		option  string
	}{
		"identity addon":           {},
		"identity zero threshold":  {option: "stream_large_bodies=0"},
		"identity threshold three": {option: "stream_large_bodies=3"},
		"chunked addon":            {chunked: true},
		"chunked zero threshold":   {chunked: true, option: "stream_large_bodies=0"},
		"chunked threshold three":  {chunked: true, option: "stream_large_bodies=3"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tests := map[string]struct{ early, close, kill bool }{
				"success: normal response":                   {},
				"success: early response continues upload":   {early: true},
				"success: early response then origin closes": {early: true, close: true},
				"error: origin closes without response":      {kill: true},
			}
			for name, outcome := range tests {
				t.Run(name, func(t *testing.T) {
					var observed *flow.HTTPFlow
					requestDone, responseDone := make(chan struct{}), make(chan struct{})
					a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
						observed = f
						if name == "request" {
							close(requestDone)
						}
						if name == "response" {
							close(responseDone)
						}
						if name == "requestheaders" && tt.option == "" {
							f.Request.Stream = true
						}
					}}
					var specs []string
					if tt.option != "" {
						specs = append(specs, tt.option)
					}
					s := newLayerSession(t, a, specs...)
					s.start(hookdata.HTTPModeRegular)
					framing, first, second, last := "Content-Length: 9\r\n\r\n", "abc", "def", "ghi"
					if tt.chunked {
						framing, first, second, last = "Transfer-Encoding: chunked\r\n\r\n", "3\r\nabc\r\n", "3\r\ndef\r\n", "3\r\nghi\r\n0\r\n\r\n"
					}
					write(t, s.client, "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"+framing+first)
					delayed := tt.chunked && tt.option == "stream_large_bodies=3"
					if delayed {
						write(t, s.client, second)
					}
					origin := await(t, s.pool.origins)
					expectRead(t, origin, "POST / HTTP/1.1\r\nHost: example.com\r\n"+framing)
					if delayed {
						expectRead(t, origin, "6\r\nabcdef\r\n")
					} else {
						expectRead(t, origin, first)
						write(t, s.client, second)
						expectRead(t, origin, second)
					}
					wantHooks := []string{"requestheaders"}
					if outcome.early {
						response := "HTTP/1.1 413 Request Entity Too Large\r\nContent-Length: 0\r\n\r\n"
						write(t, origin, response)
						expectRead(t, s.client, response)
						wantHooks = append(wantHooks, "responseheaders", "response")
					}
					if outcome.close || outcome.kill {
						if err := origin.CloseWrite(); err != nil {
							t.Fatal(err)
						}
						data, err := io.ReadAll(s.client)
						if err != nil {
							t.Fatal(err)
						}
						if outcome.kill {
							wantHooks = append(wantHooks, "error")
							if !bytes.HasPrefix(data, []byte("HTTP/1.1 502 ")) {
								t.Fatalf("early abort = %q", data)
							}
						} else if len(data) != 0 {
							t.Fatalf("completed early response followed by %q", data)
						}
					} else {
						write(t, s.client, last)
						expectRead(t, origin, last)
						await(t, requestDone)
						wantHooks = append(wantHooks, "request")
						if !outcome.early {
							response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
							write(t, origin, response)
							expectRead(t, s.client, response)
							await(t, responseDone)
							wantHooks = append(wantHooks, "responseheaders", "response")
						}
					}
					finishLayerSession(t, s, wantHooks)
					if observed == nil || observed.Live {
						t.Fatal("streamed request remains live")
					}
					if observed.Request.RawContent != nil {
						t.Fatal("streamed request body was retained")
					}
				})
			}
		})
	}
}

func TestLayerResponseStreamingMatrix(t *testing.T) {
	tests := map[string]struct {
		chunked bool
		option  string
	}{
		"identity addon":           {},
		"identity zero threshold":  {option: "stream_large_bodies=0"},
		"identity threshold three": {option: "stream_large_bodies=3"},
		"chunked addon":            {chunked: true},
		"chunked zero threshold":   {chunked: true, option: "stream_large_bodies=0"},
		"chunked threshold three":  {chunked: true, option: "stream_large_bodies=3"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var observed *flow.HTTPFlow
			responseDone := make(chan struct{})
			a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				observed = f
				if name == "response" {
					close(responseDone)
				}
				if name == "responseheaders" && tt.option == "" {
					f.Response.Stream = true
				}
			}}
			var specs []string
			if tt.option != "" {
				specs = append(specs, tt.option)
			}
			s := newLayerSession(t, a, specs...)
			s.start(hookdata.HTTPModeRegular)
			write(t, s.client, "GET http://example.com/largefile HTTP/1.1\r\nHost: example.com\r\n\r\n")
			origin := await(t, s.pool.origins)
			expectRead(t, origin, "GET /largefile HTTP/1.1\r\nHost: example.com\r\n\r\n")
			framing, first, second := "Content-Length: 6\r\n\r\n", "abc", "def"
			if tt.chunked {
				framing, first, second = "Transfer-Encoding: chunked\r\n\r\n", "3\r\nabc\r\n", "3\r\ndef\r\n"
			}
			write(t, origin, "HTTP/1.1 200 OK\r\n"+framing+first)
			delayed := tt.chunked && tt.option == "stream_large_bodies=3"
			if delayed {
				write(t, origin, second)
			}
			expectRead(t, s.client, "HTTP/1.1 200 OK\r\n"+framing)
			if delayed {
				expectRead(t, s.client, "6\r\nabcdef\r\n")
			} else {
				expectRead(t, s.client, first)
				write(t, origin, second)
				expectRead(t, s.client, second)
			}
			if tt.chunked {
				write(t, origin, "0\r\n\r\n")
				expectRead(t, s.client, "0\r\n\r\n")
			}
			await(t, responseDone)
			finishLayerSession(t, s, []string{"requestheaders", "request", "responseheaders", "response"})
			if observed.Live || observed.Response.RawContent != nil {
				t.Fatal("streamed response retained its body or remained live")
			}
		})
	}
}

func TestLayerBodyLimitWire(t *testing.T) {
	tests := map[string]struct{ response, chunked bool }{
		"error: declared request limit":     {},
		"error: accumulated request limit":  {chunked: true},
		"error: declared response limit":    {response: true},
		"error: accumulated response limit": {response: true, chunked: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var observed *flow.HTTPFlow
			a := &streamAddon{edit: func(_ string, f *flow.HTTPFlow) { observed = f }}
			s := newLayerSession(t, a, "body_size_limit=3")
			s.start(hookdata.HTTPModeRegular)
			body := "Content-Length: 6\r\n\r\nabcdef"
			if tt.chunked {
				body = "Transfer-Encoding: chunked\r\n\r\n6\r\nabcdef"
			}
			wantHooks := []string{"requestheaders"}
			status := "413 Payload Too Large"
			if tt.response {
				write(t, s.client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
				origin := await(t, s.pool.origins)
				expectRead(t, origin, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
				write(t, origin, "HTTP/1.1 200 OK\r\n"+body)
				wantHooks = append(wantHooks, "request", "responseheaders")
				status = "502 Bad Gateway"
			} else {
				write(t, s.client, "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"+body)
			}
			data, err := io.ReadAll(s.client)
			if err != nil || !bytes.Contains(data, []byte(status)) || !bytes.Contains(data, []byte("body_size_limit")) {
				t.Fatalf("body limit response = (%q, %v)", data, err)
			}
			finishLayerSession(t, s, append(wantHooks, "error"))
			if observed == nil || observed.Live {
				t.Fatal("oversized flow remains live")
			}
		})
	}
}

func TestLayerStoredStreamTransforms(t *testing.T) {
	tests := map[string]struct{ store bool }{
		"success: transformed bodies discarded": {},
		"success: transformed bodies stored":    {store: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var observed *flow.HTTPFlow
			a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				observed = f
				transform := func(chunk []byte) [][]byte { return [][]byte{fmt.Appendf(nil, "[%s]", chunk)} }
				if name == "requestheaders" {
					f.Request.StreamFunc = transform
				}
				if name == "responseheaders" {
					f.Response.StreamFunc = transform
				}
			}}
			s := newLayerSession(t, a, fmt.Sprintf("store_streamed_bodies=%v", tt.store))
			s.start(hookdata.HTTPModeRegular)
			write(t, s.client, "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
			origin := await(t, s.pool.origins)
			expectRead(t, origin, "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n[abc]\r\n2\r\n[]\r\n0\r\n\r\n")
			write(t, origin, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\ndef\r\n0\r\n\r\n")
			expectRead(t, s.client, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n[def]\r\n2\r\n[]\r\n0\r\n\r\n")
			finishLayerSession(t, s, []string{"requestheaders", "request", "responseheaders", "response"})
			var wantRequest, wantResponse []byte
			if tt.store {
				wantRequest, wantResponse = []byte("[abc][]"), []byte("[def][]")
			}
			if diff := gocmp.Diff(wantRequest, observed.Request.RawContent); diff != "" {
				t.Fatalf("stored request (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(wantResponse, observed.Response.RawContent); diff != "" {
				t.Fatalf("stored response (-want +got):\n%s", diff)
			}
		})
	}
}
