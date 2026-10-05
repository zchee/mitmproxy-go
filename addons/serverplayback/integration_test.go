// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package serverplayback

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func replayRequest(t *testing.T, p *proxytest.Proxy, r *httpmsg.Request) (*httpmsg.Response, error) {
	t.Helper()
	conn, err := net.Dial("tcp", p.Addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, err
	}
	request := r.Clone()
	request.Authority = net.JoinHostPort(r.Host, fmt.Sprint(r.Port))
	head := http1.AssembleRequestHead(request, nil, false, nil)
	if _, err := conn.Write(head); err != nil {
		return nil, err
	}
	size, err := http1.ExpectedBodySize(request, nil)
	if err != nil {
		return nil, err
	}
	writer, err := http1.NewBodyWriter(conn, size)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(request.RawContent); err != nil {
		return nil, err
	}
	if err := writer.Close(request.Trailers); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http1.ReadResponseHead(reader)
	if err != nil {
		return nil, err
	}
	size, err = http1.ExpectedBodySize(request, response.Response)
	if err != nil {
		return nil, err
	}
	body, err := http1.NewBodyReader(reader, size)
	if err != nil {
		return nil, err
	}
	response.Response.RawContent, err = io.ReadAll(body)
	response.Response.Trailers = body.Trailers()
	return response.Response, err
}

func TestProxyReplayPolicies(t *testing.T) {
	tests := map[string]struct {
		extra  string
		ignore bool
		match  bool
		status int
		kill   bool
	}{"success: recorded request": {match: true, status: 200}, "success: ignored query parameter": {ignore: true, match: true, status: 200}, "success: kill unmatched": {extra: "kill", kill: true}, "success: forward unmatched": {extra: "forward", status: 201}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			origin := proxytest.StartHTTPOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(201) }))
			p := proxytest.Start(t, proxytest.WithOrigin("replay.test", origin))
			s := New(p.Master)
			if err := p.Master.Addons.Add(t.Context(), s); err != nil {
				t.Fatal(err)
			}
			recorded := testflow.TFlow(testflow.WithResponse)
			recorded.Request.Host = "replay.test"
			recorded.Request.Port = 80
			recorded.Request.SetHostHeader("replay.test")
			recorded.Request.Path = "/path?nonce=old"
			req := recorded.Request.Clone()
			if tt.ignore {
				req.Path = "/path?nonce=new"
			} else if !tt.match {
				req.Path = "/missing"
			}
			if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
				opts := map[string]any{"server_replay_refresh": false}
				if tt.extra != "" {
					opts["server_replay_extra"] = tt.extra
				}
				if tt.ignore {
					opts["server_replay_ignore_params"] = []string{"nonce"}
				}
				if err := p.Master.Options.Update(ctx, opts); err != nil {
					return err
				}
				return s.loadFlows(ctx, []flow.Flow{recorded})
			}); err != nil {
				t.Fatal(err)
			}
			response, err := replayRequest(t, p, req)
			if tt.kill {
				if err == nil {
					t.Fatal("unmatched request not killed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tt.status {
				t.Fatalf("status=%d want %d body=%s", response.StatusCode, tt.status, response.RawContent)
			}
			if tt.match {
				if diff := cmp.Diff(recorded.Response.Headers, response.Headers); diff != "" {
					t.Fatal(diff)
				}
				if diff := cmp.Diff(recorded.Response.RawContent, response.RawContent); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

func TestProxyReplayFixtures(t *testing.T) {
	paths, err := filepath.Glob("../../testdata/mitmproxy/flows/*.mitm")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct{ f *flow.HTTPFlow }{}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		index := 0
		for f, err := range flowio.NewReader(file).All() {
			if err != nil {
				t.Fatal(err)
			}
			h, ok := f.(*flow.HTTPFlow)
			if ok && h.Request != nil && h.Response != nil && !h.Request.IsHTTP2() && !h.Request.IsHTTP3() && h.Request.RawContent != nil {
				tests[fmt.Sprintf("success: %s %d", filepath.Base(path), index)] = struct{ f *flow.HTTPFlow }{h}
			}
			index++
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if len(tests) == 0 {
		t.Fatal("no replayable HTTP/1 fixtures")
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p := proxytest.Start(t)
			s := New(p.Master)
			if err := p.Master.Addons.Add(t.Context(), s); err != nil {
				t.Fatal(err)
			}
			if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
				if err := p.Master.Options.Update(ctx, map[string]any{"server_replay_refresh": false, "validate_inbound_headers": false}); err != nil {
					return err
				}
				return s.loadFlows(ctx, []flow.Flow{tt.f})
			}); err != nil {
				t.Fatal(err)
			}
			response, err := replayRequest(t, p, tt.f.Request)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tt.f.Response.StatusCode {
				t.Fatalf("status=%d want %d", response.StatusCode, tt.f.Response.StatusCode)
			}
			if diff := cmp.Diff(tt.f.Response.Headers, response.Headers); diff != "" {
				t.Fatal(diff)
			}
			if diff := cmp.Diff(tt.f.Response.RawContent, response.RawContent); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
