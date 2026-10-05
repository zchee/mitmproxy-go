// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package clientplayback

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(30 * time.Second):
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		t.Fatalf("replay hang detector expired\n%s", stack[:n])
	}
	var zero T
	return zero
}

func leakCheck(t *testing.T) {
	t.Helper()
	ignored := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, ignored) })
}

func stopPlayback(t *testing.T, p *proxytest.Proxy, c *ClientPlayback) {
	t.Helper()
	if err := p.Master.Addons.Hook(t.Context(), addon.DoneHook{}); err != nil {
		t.Fatal(err)
	}
	if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
		if c.count(ctx) != 0 {
			t.Fatalf("replay count=%d after join", c.count(ctx))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type lifecycleObserver struct {
	requests  chan *flow.HTTPFlow
	completed chan *flow.HTTPFlow
}

func (o *lifecycleObserver) Request(_ context.Context, f *flow.HTTPFlow) error {
	o.requests <- f
	return nil
}

func (o *lifecycleObserver) Response(_ context.Context, f *flow.HTTPFlow) error {
	o.completed <- f
	return nil
}

func (o *lifecycleObserver) Error(_ context.Context, f *flow.HTTPFlow) error {
	o.completed <- f
	return nil
}

func TestPlayback(t *testing.T) {
	tests := map[string]struct {
		mode        string
		concurrency int
	}{
		"success: HTTP sequential": {"http", 1}, "success: HTTP concurrent": {"http", -1},
		"success: HTTPS sequential": {"https", 1}, "success: HTTPS concurrent": {"https", -1},
		"success: upstream sequential": {"upstream", 1}, "success: upstream concurrent": {"upstream", -1},
		"error: origin disconnect sequential": {"err", 1}, "error: origin disconnect concurrent": {"err", -1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			leakCheck(t)
			wire := make(chan string, 1)
			closed := make(chan struct{}, 1)
			handler := func(conn net.Conn) {
				defer func() { closed <- struct{}{} }()
				if tt.mode == "err" {
					return
				}
				if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
					t.Error(err)
					return
				}
				reader := bufio.NewReader(conn)
				var request strings.Builder
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						t.Error(err)
						return
					}
					request.WriteString(line)
					if line == "\r\n" {
						break
					}
				}
				body := make([]byte, 4)
				if _, err := io.ReadFull(reader, body); err != nil {
					t.Error(err)
					return
				}
				request.Write(body)
				wire <- request.String()
				if _, err := io.WriteString(conn, "HTTP/1.1 204 No Content\r\n\r\n"); err != nil {
					t.Error(err)
					return
				}
				if _, err := reader.ReadByte(); err != io.EOF {
					t.Errorf("replay origin close=%v", err)
				}
			}
			var origin *proxytest.Origin
			if tt.mode == "https" {
				origin = proxytest.StartTLSOrigin(t, []string{"example.mitmproxy.org"}, handler)
			} else {
				origin = proxytest.StartOrigin(t, handler)
			}
			var opts []proxytest.Option
			if origin.CA != nil {
				opts = append(opts, proxytest.WithTrustedCA(origin.CA))
			}
			p := proxytest.Start(t, opts...)
			c := New(p.Master)
			observer := &lifecycleObserver{requests: make(chan *flow.HTTPFlow, 1), completed: make(chan *flow.HTTPFlow, 1)}
			if err := p.Master.Addons.Add(t.Context(), c, observer); err != nil {
				t.Fatal(err)
			}
			f := testflow.TFlow()
			f.Live = false
			f.Request.RawContent = []byte("data")
			f.Request.Headers.Set("content-length", "4")
			f.Request.SetHostHeader("example.mitmproxy.org")
			f.Request.Authority = ""
			host, port, err := net.SplitHostPort(origin.Addr)
			if err != nil {
				t.Fatal(err)
			}
			f.Request.Host = host
			f.Request.Port, err = strconv.Atoi(port)
			if err != nil {
				t.Fatal(err)
			}
			values := map[string]any{"client_replay_concurrency": tt.concurrency}
			if tt.mode == "https" {
				f.Request.Scheme = "https"
			}
			if tt.mode == "upstream" {
				values["mode"] = []string{"upstream:http://" + origin.Addr}
				f.Request.Host = "address"
				f.Request.Port = 22
				f.Request.Authority = origin.Addr
			}
			if err := p.Master.Do(t.Context(), func(ctx context.Context) error { return p.Master.Options.Update(ctx, values) }); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Master.Call(t.Context(), "replay.client", []flow.Flow{f}); err != nil {
				t.Fatal(err)
			}
			if err := p.Master.Addons.Hook(t.Context(), addon.RunningHook{}); err != nil {
				t.Fatal(err)
			}
			if tt.mode != "err" {
				path := "/path"
				if tt.mode == "upstream" {
					path = "http://address:22/path"
				}
				want := fmt.Sprintf("GET %s HTTP/1.1\r\nheader: qvalue\r\ncontent-length: 4\r\nHost: example.mitmproxy.org\r\n\r\ndata", path)
				if diff := cmp.Diff(want, await(t, wire)); diff != "" {
					t.Fatal(diff)
				}
			}
			if got := await(t, observer.requests); got != f {
				t.Fatal("request hook received a replacement flow")
			}
			if got := await(t, observer.completed); got != f {
				t.Fatal("terminal hook received a replacement flow")
			}
			await(t, closed)
			stopPlayback(t, p, c)
			if err := p.Master.Do(t.Context(), func(context.Context) error {
				if tt.mode == "err" {
					if f.Error == nil {
						t.Fatal("disconnect did not set flow error")
					}
				} else if f.Response == nil || f.Response.StatusCode != 204 {
					t.Fatalf("response=%v error=%v", f.Response, f.Error)
				}
				if f.IsReplay == nil || *f.IsReplay != "request" {
					t.Fatal("replay marker lost")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPlaybackHTTPSUpstream(t *testing.T) {
	leakCheck(t)
	wire := make(chan string, 1)
	closed := make(chan struct{}, 1)
	origin := proxytest.StartOrigin(t, func(conn net.Conn) {
		defer func() { closed <- struct{}{} }()
		if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Error(err)
			return
		}
		reader := bufio.NewReader(conn)
		var text strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Error(err)
				return
			}
			text.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		wire <- text.String()
		if _, err := io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n"); err != nil {
			t.Error(err)
		}
		if _, err := reader.ReadByte(); err != io.EOF {
			t.Error(err)
		}
	})
	p := proxytest.Start(t)
	c := New(p.Master)
	observer := &lifecycleObserver{requests: make(chan *flow.HTTPFlow, 1), completed: make(chan *flow.HTTPFlow, 1)}
	if err := p.Master.Addons.Add(t.Context(), c, observer); err != nil {
		t.Fatal(err)
	}
	f := testflow.TFlow()
	f.Live = false
	f.Request.Scheme = "https"
	f.Request.Host = "address"
	f.Request.Port = 22
	if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
		return p.Master.Options.Update(ctx, map[string]any{"mode": []string{"upstream:http://" + origin.Addr}})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Master.Call(t.Context(), "replay.client", []flow.Flow{f}); err != nil {
		t.Fatal(err)
	}
	if err := p.Master.Addons.Hook(t.Context(), addon.RunningHook{}); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff("CONNECT address:22 HTTP/1.1\r\nHost: address:22\r\n\r\n", await(t, wire)); diff != "" {
		t.Fatal(diff)
	}
	if got := await(t, observer.completed); got != f {
		t.Fatal("CONNECT error hook received a replacement flow")
	}
	await(t, closed)
	stopPlayback(t, p, c)
	if err := p.Master.Do(t.Context(), func(context.Context) error {
		want := "Upstream proxy " + origin.Addr + " refused HTTP CONNECT request: 502 Bad Gateway"
		if f.Error == nil || f.Error.Msg != want || f.Response != nil {
			t.Fatalf("response=%v error=%v want=%s", f.Response, f.Error, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReplayCountAndCancellation(t *testing.T) {
	tests := map[string]struct {
		concurrency int
		started     int
	}{"success: sequential": {concurrency: 1, started: 1}, "success: concurrent": {concurrency: -1, started: 2}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			leakCheck(t)
			entered := make(chan struct{}, 2)
			closed := make(chan struct{}, 2)
			origin := proxytest.StartOrigin(t, func(conn net.Conn) {
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				entered <- struct{}{}
				_, _ = io.Copy(io.Discard, reader)
				closed <- struct{}{}
			})
			p := proxytest.Start(t)
			c := New(p.Master)
			if err := p.Master.Addons.Add(t.Context(), c); err != nil {
				t.Fatal(err)
			}
			host, port, _ := net.SplitHostPort(origin.Addr)
			number, _ := strconv.Atoi(port)
			var flows []flow.Flow
			for range 2 {
				f := testflow.TFlow()
				f.Live = false
				f.Request.Host = host
				f.Request.Port = number
				f.Request.RawContent = []byte{}
				f.Request.Headers.Del("content-length")
				flows = append(flows, f)
			}
			if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
				return p.Master.Options.Update(ctx, map[string]any{"client_replay_concurrency": tt.concurrency})
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Master.Call(t.Context(), "replay.client", flows); err != nil {
				t.Fatal(err)
			}
			if err := p.Master.Addons.Hook(t.Context(), addon.RunningHook{}); err != nil {
				t.Fatal(err)
			}
			for range tt.started {
				await(t, entered)
			}
			if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
				if c.count(ctx) != 2 || c.active != tt.started {
					t.Fatalf("count=%d active=%d", c.count(ctx), c.active)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Master.Call(t.Context(), "replay.client.stop"); err != nil {
				t.Fatal(err)
			}
			if err := p.Master.Addons.Hook(t.Context(), addon.DoneHook{}); err != nil {
				t.Fatal(err)
			}
			for range tt.started {
				await(t, closed)
			}
			if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
				if c.count(ctx) != 0 {
					t.Fatal("active replay retained after cancellation")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Preserve request order and trailers when the recorded request uses chunks.
func TestReplayTrailers(t *testing.T) {
	leakCheck(t)
	observed := make(chan string, 1)
	closed := make(chan struct{}, 1)
	origin := proxytest.StartOrigin(t, func(conn net.Conn) {
		defer func() { closed <- struct{}{} }()
		reader := bufio.NewReader(conn)
		var text strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Error(err)
				return
			}
			text.WriteString(line)
			if line == "Checksum: yes\r\n" {
				line, err = reader.ReadString('\n')
				if err != nil {
					t.Error(err)
					return
				}
				text.WriteString(line)
				break
			}
		}
		observed <- text.String()
		_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\n\r\n")
		_, _ = io.Copy(io.Discard, reader)
	})
	p := proxytest.Start(t)
	c := New(p.Master)
	if err := p.Master.Addons.Add(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	f := testflow.TFlow()
	f.Live = false
	host, port, _ := net.SplitHostPort(origin.Addr)
	f.Request.Host = host
	f.Request.Port, _ = strconv.Atoi(port)
	f.Request.Authority = ""
	f.Request.Headers.Del("content-length")
	f.Request.Headers.Set("Transfer-Encoding", "chunked")
	f.Request.RawContent = []byte("data")
	f.Request.Trailers = httpmsg.Headers{{Name: []byte("Checksum"), Value: []byte("yes")}}
	if _, err := p.Master.Call(t.Context(), "replay.client", []flow.Flow{f}); err != nil {
		t.Fatal(err)
	}
	if err := p.Master.Addons.Hook(t.Context(), addon.RunningHook{}); err != nil {
		t.Fatal(err)
	}
	if got := await(t, observed); !strings.HasSuffix(got, "4\r\ndata\r\n0\r\nChecksum: yes\r\n\r\n") {
		t.Fatal(got)
	}
	await(t, closed)
	stopPlayback(t, p, c)
}
