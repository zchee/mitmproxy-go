// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dump

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addons/proxyserver"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/tools/cmdline"
)

type httpProbe struct {
	running   chan struct{}
	requests  chan string
	responses chan int
}

func (p *httpProbe) Running(context.Context) error {
	close(p.running)
	return nil
}

func (p *httpProbe) Request(_ context.Context, f *flow.HTTPFlow) error {
	p.requests <- f.Request.Method
	return nil
}

func (p *httpProbe) Response(_ context.Context, f *flow.HTTPFlow) error {
	p.responses <- f.Response.StatusCode
	return nil
}

func awaitHTTP[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(10 * time.Second):
		var stacks strings.Builder
		_ = pprof.Lookup("goroutine").WriteTo(&stacks, 2)
		t.Fatalf("HTTP lifecycle did not complete:\n%s", stacks.String())
		var zero T
		return zero
	}
}

// startHTTPDump uses the command's option parser and the production addon set.
// Importing proxytest here would register its layers and hide missing imports
// in the dump assembly.
func startHTTPDump(t *testing.T, mode string, stdout io.Writer) (*Master, string, *httpProbe) {
	t.Helper()
	m := newMaster(t, Config{Stdout: stdout, Stderr: io.Discard, WithTermlog: true, WithDumper: true})
	cmd := cmdline.New(m.Options, "test")
	if err := cmd.ParseFlags([]string{"--mode", mode, "--listen-host", "127.0.0.1", "--listen-port", "0", "--set", "confdir=" + t.TempDir(), "--set", "termlog_verbosity=debug"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdline.Apply(t.Context(), cmd, m.Options, m.Do); err != nil {
		t.Fatal(err)
	}
	probe := &httpProbe{running: make(chan struct{}), requests: make(chan string, 1), responses: make(chan int, 1)}
	if err := m.Addons.Add(t.Context(), probe); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- m.Run(t.Context()) }()
	t.Cleanup(func() {
		m.Shutdown()
		if err := awaitHTTP(t, done); err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	awaitHTTP(t, probe.running)
	ps, ok := m.Addons.Get("proxyserver").(*proxyserver.ProxyServer)
	if !ok {
		t.Fatal("dump master has no proxyserver")
	}
	addrs := ps.ListenAddrs()
	if len(addrs) != 1 {
		t.Fatalf("listener addresses = %v, want one loopback listener", addrs)
	}
	return m, addrs[0].String(), probe
}

func TestHTTPProxyAssembly(t *testing.T) {
	const body = "response from the real origin"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/assembly" {
			t.Errorf("origin request = %s %s, want GET /assembly", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, body)
	}))
	defer origin.Close()
	tests := map[string]struct {
		mode    string
		forward bool
	}{
		"success: regular": {mode: "regular", forward: true},
		"success: reverse": {mode: "reverse:" + origin.URL},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, addr, probe := startHTTPDump(t, tt.mode, io.Discard)
			transport := &http.Transport{DisableKeepAlives: true}
			t.Cleanup(transport.CloseIdleConnections)
			target := "http://" + addr + "/assembly"
			if tt.forward {
				transport.Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: addr})
				target = origin.URL + "/assembly"
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := (&http.Client{Transport: transport}).Do(req)
			if err != nil {
				t.Fatalf("GET through assembled dump master: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(body, string(got)); diff != "" {
				t.Errorf("response body (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(http.MethodGet, awaitHTTP(t, probe.requests)); diff != "" {
				t.Errorf("request hook (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(http.StatusOK, awaitHTTP(t, probe.responses)); diff != "" {
				t.Errorf("response hook (-want +got):\n%s", diff)
			}
		})
	}
}
