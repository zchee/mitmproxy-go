// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package clientplayback

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestSavedHTTP2Replay(t *testing.T) {
	tests := map[string]struct{ originHTTP2 bool }{
		"success: saved h2 request to h1 TLS origin": {},
		"success: saved h2 request to h2 TLS origin": {originHTTP2: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			leakCheck(t)
			observed := make(chan int, 1)
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				if diff := gocmp.Diff("saved-body", string(body)); diff != "" {
					t.Error(diff)
				}
				if diff := gocmp.Diff([]string{"one", "two"}, r.Header.Values("X-Duplicate")); diff != "" {
					t.Error(diff)
				}
				if r.Host != "saved.test" {
					t.Errorf("origin authority = %q", r.Host)
				}
				observed <- r.ProtoMajor
				w.Header().Set("Trailer", "X-Final")
				if _, err := io.WriteString(w, "replayed"); err != nil {
					t.Error(err)
				}
				w.Header().Set("X-Final", "last")
			}))
			origin.EnableHTTP2 = tt.originHTTP2
			origin.StartTLS()
			t.Cleanup(origin.Close)
			p := proxytest.Start(t, proxytest.WithOptions(map[string]any{"ssl_insecure": true}))
			host, port, err := net.SplitHostPort(origin.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			number, err := strconv.Atoi(port)
			if err != nil {
				t.Fatal(err)
			}
			playback := New(p.Master)
			observer := &lifecycleObserver{requests: make(chan *flow.HTTPFlow, 1), completed: make(chan *flow.HTTPFlow, 1)}
			if err := p.Master.Addons.Add(t.Context(), playback, observer); err != nil {
				t.Fatal(err)
			}
			saved := testflow.TFlow()
			saved.Live = false
			saved.Request.Method, saved.Request.Scheme, saved.Request.Host, saved.Request.Port = "POST", "https", host, number
			saved.Request.Authority, saved.Request.HTTPVersion = "saved.test", "HTTP/2.0"
			saved.Request.RawContent = []byte("saved-body")
			saved.Request.Headers = httpmsg.Headers{}
			saved.Request.Headers.Set("Content-Length", "10")
			saved.Request.Headers.Set("Host", "saved.test")
			saved.Request.Headers.Add("X-Duplicate", "one")
			saved.Request.Headers.Add("X-Duplicate", "two")
			saved.ClientConn.ALPN = []byte("h2")
			saved.ClientConn.ALPNOffers = [][]byte{[]byte("h2"), []byte("http/1.1")}
			path := filepath.Join(t.TempDir(), "saved.flow")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := flowio.NewWriter(file).Add(saved); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Master.Call(t.Context(), "replay.client.file", command.Path(path)); err != nil {
				t.Fatal(err)
			}
			if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
				if playback.count(ctx) != 1 {
					t.Fatalf("saved HTTP/2 replay queue = %d, want 1", playback.count(ctx))
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := p.Master.Addons.Hook(t.Context(), addon.RunningHook{}); err != nil {
				t.Fatal(err)
			}
			requestFlow := await(t, observer.requests)
			completed := await(t, observer.completed)
			stopPlayback(t, p, playback)
			if err := p.Master.Do(t.Context(), func(context.Context) error {
				if completed != requestFlow {
					t.Error("replay replaced its flow between lifecycle hooks")
				}
				if completed.Error != nil || completed.Response == nil {
					t.Fatalf("replay response = %v; error = %v", completed.Response, completed.Error)
				}
				if got := string(completed.Response.RawContent); got != "replayed" {
					t.Errorf("response body = %q", got)
				}
				if completed.Request.HTTPVersion != "HTTP/2.0" {
					t.Errorf("saved request version = %q", completed.Request.HTTPVersion)
				}
				if got := completed.Response.Trailers.Get("X-Final"); got != "last" {
					t.Errorf("saved response trailer = %q", got)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			want := 1
			if tt.originHTTP2 {
				want = 2
			}
			if got := await(t, observed); got != want {
				t.Errorf("origin protocol = HTTP/%d, want HTTP/%d", got, want)
			}
		})
	}
}
