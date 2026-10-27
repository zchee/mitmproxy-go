// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

type liveFixture struct {
	c             *Controller
	m             *master.Master
	dispatchEnded chan struct{}
}

func liveController(t *testing.T, cfg Config, tlsConfig *tls.Config) *liveFixture {
	t.Helper()
	c := New(cfg)
	c.tlsConfig = tlsConfig
	dispatchEnded := make(chan struct{}, 64)
	m := master.New(master.Config{OnHookComplete: c.OnHookComplete, OnDispatchStart: c.OnDispatchStart, OnDispatchEnd: func() {
		c.OnDispatchEnd()
		select {
		case dispatchEnded <- struct{}{}:
		default:
		}
	}})
	c.Bind(m)
	if err := m.Addons.Add(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	if err := m.Addons.Trigger(t.Context(), addon.RunningHook{}); err != nil {
		t.Fatal(err)
	}
	x := &liveFixture{c: c, m: m, dispatchEnded: dispatchEnded}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 12*time.Second)
		defer cancel()
		if err := c.Close(ctx); err != nil {
			t.Error(err)
		}
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return x
}

func setEndpoint(t *testing.T, x *liveFixture, value string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	if err := x.m.Do(ctx, func(ctx context.Context) error { return x.m.Options.Update(ctx, map[string]any{endpointOption: value}) }); err != nil {
		t.Fatal(err)
	}
	if err := x.c.Sync(ctx); err != nil {
		t.Fatal(err)
	}
}

func liveHook(t *testing.T, x *liveFixture, event addon.Hook) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := x.m.Addons.Hook(ctx, event); err != nil {
		t.Fatal(err)
	}
}

func currentGeneration(x *liveFixture) *generation {
	x.c.admit.Lock()
	defer x.c.admit.Unlock()
	return x.c.current
}

func flushLive(t *testing.T, x *liveFixture) error {
	t.Helper()
	g := currentGeneration(x)
	if g == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	return errors.Join(g.traces.ForceFlush(ctx), g.meters.ForceFlush(ctx))
}

func assertJoined(t *testing.T, g *generation) {
	t.Helper()
	if g == nil {
		return
	}
	if !g.closed.Load() {
		t.Error("generation has no closed acknowledgement")
	}
	for _, life := range []*exportLifetime{&g.spanExport.life, &g.metricExport.life} {
		life.mu.Lock()
		count := life.inflight
		life.mu.Unlock()
		if count != 0 {
			t.Errorf("residual export count=%d", count)
		}
		select {
		case <-life.shutdown:
		default:
			t.Error("exporter shutdown/drain acknowledgement missing")
		}
	}
}

func childCase(t *testing.T, extra ...string) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run", "^"+regexp.QuoteMeta(t.Name())+"$", "-test.count=1", "-test.timeout=15s", "-test.v")
	cmd.WaitDelay = time.Second
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "SYSTEMROOT=" + os.Getenv("SYSTEMROOT"), "MITMPROXY_TELEMETRY_CHILD=1"}, extra...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bounded policy child failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "--- PASS: "+t.Name()+" (") || strings.Contains(string(output), "--- SKIP:") || strings.Contains(string(output), "no tests to run") {
		t.Fatalf("child did not prove the selected contract: %s", output)
	}
}

type stalledCollector struct {
	server      *httptest.Server
	started     chan struct{}
	changed     chan struct{}
	requests    atomic.Int64
	connections atomic.Int64
}

func newStalledCollector(t *testing.T) *stalledCollector {
	t.Helper()
	s := &stalledCollector{started: make(chan struct{}, 8), changed: make(chan struct{}, 32)}
	notify := func() {
		select {
		case s.changed <- struct{}{}:
		default:
		}
	}
	s.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		defer func() { s.requests.Add(-1); notify() }()
		count, err := io.Copy(io.Discard, io.LimitReader(r.Body, (1<<20)+1))
		if err != nil || count > 1<<20 {
			if r.Context().Err() == nil {
				t.Errorf("stalled collector request invalid: bytes=%d err=%v", count, err)
			}
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case s.started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	s.server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			s.connections.Add(1)
		case http.StateClosed, http.StateHijacked:
			s.connections.Add(-1)
			notify()
		}
	}
	s.server.Start()
	t.Cleanup(s.server.Close)
	return s
}

func awaitSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	select {
	case <-ch:
	case <-ctx.Done():
		t.Fatalf("owned operation did not acknowledge: %v", ctx.Err())
	}
}

func (s *stalledCollector) joined(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	for s.requests.Load() != 0 || s.connections.Load() != 0 {
		select {
		case <-s.changed:
		case <-ctx.Done():
			t.Fatalf("collector work remains: requests=%d connections=%d", s.requests.Load(), s.connections.Load())
		}
	}
}

type rejectingEndpoint struct {
	opts  *options.Manager
	value string
}

func (r *rejectingEndpoint) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, ok := updated[endpointOption]; ok && r.opts.Str(endpointOption) == r.value {
		return &options.OptionsError{Msg: "owned rejection"}
	}
	return nil
}

func TestTelemetryExporter(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"empty_no_io": {func(t *testing.T) {
			c := New(Config{})
			m := master.New(master.Config{OnHookComplete: c.OnHookComplete})
			c.Bind(m)
			if err := m.Addons.Add(t.Context(), c); err != nil {
				t.Fatal(err)
			}
			metadata, ok := m.Options.Lookup(endpointOption)
			if !ok || metadata.Type() != options.TypeStr || metadata.Default() != "" || metadata.Help() != "OTLP endpoint that OpenTelemetry traces and metrics are exported to. Empty disables the exporter." {
				t.Fatal("option metadata differs from the Go-only manifest")
			}
			if c.started || c.current != nil {
				t.Fatal("metadata-only construction started telemetry")
			}
			if err := c.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
		}},
		"http_loopback": {func(t *testing.T) {
			collector := newOwnedCollector(t, false)
			x := liveController(t, Config{Version: "test"}, nil)
			setEndpoint(t, x, collector.server.URL)
			liveHook(t, x, addon.ResponseHook{Flow: httpFlow(t)})
			if err := flushLive(t, x); err != nil {
				t.Fatal(err)
			}
			if len(collector.spans()) != 1 {
				t.Fatal("real HTTP collector did not receive one flow")
			}
			collector.mu.Lock()
			count := len(collector.metrics)
			collector.mu.Unlock()
			if count == 0 {
				t.Fatal("real HTTP collector did not receive SDK metrics")
			}
		}},
		"https_verified": {func(t *testing.T) {
			collector := newOwnedCollector(t, true)
			roots := x509.NewCertPool()
			roots.AddCert(collector.server.Certificate())
			x := liveController(t, Config{Version: "test"}, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
			setEndpoint(t, x, collector.server.URL)
			liveHook(t, x, addon.ResponseHook{Flow: httpFlow(t)})
			if err := flushLive(t, x); err != nil {
				t.Fatal(err)
			}
			if len(collector.spans()) != 1 {
				t.Fatal("verified HTTPS export missing")
			}
			client, transport := newHTTPClient(nil, nil)
			defer transport.CloseIdleConnections()
			response, err := client.Get(collector.server.URL + "/v1/traces")
			if response != nil {
				_ = response.Body.Close()
			}
			if err == nil {
				t.Fatal("untrusted HTTPS certificate was accepted")
			}
		}},
		"plaintext_remote_refused": {func(t *testing.T) {
			for _, value := range []string{"http://example.com", "http://192.0.2.1", "http://0.0.0.0:4318", "http://[::]:4318"} {
				if _, err := parseEndpoint(value); err == nil {
					t.Fatalf("plaintext remote accepted: %q", value)
				}
			}
		}},
		"endpoint_paths": {func(t *testing.T) {
			for _, base := range []string{"http://127.0.0.1:4318", "http://127.0.0.1:4318/prefix/", "https://example.test/base%2Ftenant"} {
				e, err := parseEndpoint(base)
				if err != nil {
					t.Fatal(err)
				}
				for _, signal := range []string{"traces", "metrics"} {
					u, err := url.Parse(e.signalURL(signal))
					if err != nil || !strings.HasSuffix(u.EscapedPath(), "/v1/"+signal) {
						t.Fatalf("signal URL=%q err=%v", e.signalURL(signal), err)
					}
					if strings.Contains(base, "%2F") && !strings.Contains(u.EscapedPath(), "%2F") {
						t.Fatal("encoded base path was lost")
					}
				}
			}
		}},
		"credentials_refused": {func(t *testing.T) {
			for _, value := range []string{"https://user:pass@example.test", "https://example.test?token=x", "https://example.test#fragment", "ftp://example.test", "https://example.test:70000", "https://example.test:", strings.Repeat("x", 4097)} {
				if _, err := parseEndpoint(value); err == nil {
					t.Fatal("invalid endpoint accepted")
				}
			}
		}},
		"headers_environment_ignored": {func(t *testing.T) {
			if os.Getenv("MITMPROXY_TELEMETRY_CHILD") == "" {
				childCase(t, "OTEL_EXPORTER_OTLP_ENDPOINT=http://192.0.2.1:4318", "OTEL_EXPORTER_OTLP_HEADERS=Authorization=private,leak=private", "OTEL_EXPORTER_OTLP_TRACES_HEADERS=Authorization=private", "OTEL_EXPORTER_OTLP_METRICS_HEADERS=Authorization=private", "HTTP_PROXY=http://192.0.2.1:8080")
				return
			}
			collector := newOwnedCollector(t, false)
			x := liveController(t, Config{}, nil)
			setEndpoint(t, x, collector.server.URL)
			liveHook(t, x, addon.ResponseHook{Flow: httpFlow(t)})
			if err := flushLive(t, x); err != nil {
				t.Fatal(err)
			}
			collector.mu.Lock()
			defer collector.mu.Unlock()
			if len(collector.headers) < 2 {
				t.Fatal("both real exporters were not observed")
			}
			for _, headers := range collector.headers {
				if headers.Get("Authorization") != "" || headers.Get("Leak") != "" {
					t.Fatal("environment headers escaped the owned boundary")
				}
			}
			if currentGeneration(x).transport.Proxy != nil {
				t.Fatal("owned transport inherited a proxy")
			}
		}},
		"self_listener_refused": {func(t *testing.T) {
			collector := newOwnedCollector(t, false)
			u, err := url.Parse(collector.server.URL)
			if err != nil {
				t.Fatal(err)
			}
			address, err := netip.ParseAddrPort(u.Host)
			if err != nil {
				t.Fatal(err)
			}
			x := liveController(t, Config{Listeners: func() []netip.AddrPort {
				return []netip.AddrPort{netip.AddrPortFrom(netip.IPv4Unspecified(), address.Port())}
			}}, nil)
			setEndpoint(t, x, collector.server.URL)
			liveHook(t, x, addon.ResponseHook{Flow: httpFlow(t)})
			_ = flushLive(t, x)
			if len(collector.spans()) != 0 || x.c.Status().ExportFailures == 0 {
				t.Fatal("self-listener was not refused before export")
			}
		}},
		"redirect_refused": {func(t *testing.T) {
			destination := newOwnedCollector(t, false)
			var requests atomic.Int64
			redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				http.Redirect(w, r, destination.server.URL+"/v1/traces", http.StatusTemporaryRedirect)
			}))
			defer redirect.Close()
			x := liveController(t, Config{}, nil)
			setEndpoint(t, x, redirect.URL)
			liveHook(t, x, addon.ResponseHook{Flow: httpFlow(t)})
			_ = flushLive(t, x)
			if requests.Load() == 0 || len(destination.spans()) != 0 || x.c.Status().ExportFailures == 0 {
				t.Fatal("collector redirect crossed the owned boundary")
			}
		}},
		"queue_saturation": {func(t *testing.T) {
			collector := newStalledCollector(t)
			x := liveController(t, Config{}, nil)
			setEndpoint(t, x, collector.server.URL)
			var retained []*flow.HTTPFlow
			for range 128 {
				f := httpFlow(t)
				retained = append(retained, f)
				liveHook(t, x, addon.ResponseHook{Flow: f})
			}
			awaitSignal(t, collector.started)
			for range 1025 {
				f := httpFlow(t)
				retained = append(retained, f)
				liveHook(t, x, addon.ResponseHook{Flow: f})
			}
			if x.c.Status().QueuePressure == 0 {
				t.Fatal("saturated export queue produced no bounded diagnostic")
			}
			liveHook(t, x, addon.ClientConnectedHook{})
			g := currentGeneration(x)
			if err := x.c.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			assertJoined(t, g)
			collector.joined(t)
			runtime.KeepAlive(retained)
		}},
		"dead_collector": {func(t *testing.T) {
			unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
			defer unavailable.Close()
			x := liveController(t, Config{}, nil)
			setEndpoint(t, x, unavailable.URL)
			liveHook(t, x, addon.ResponseHook{Flow: httpFlow(t)})
			_ = flushLive(t, x)
			if x.c.Status().ExportFailures == 0 {
				t.Fatal("unavailable collector failure was not diagnosed")
			}
			liveHook(t, x, addon.ClientConnectedHook{})
		}},
		"flush_shutdown": {func(t *testing.T) {
			collector := newOwnedCollector(t, false)
			x := liveController(t, Config{}, nil)
			setEndpoint(t, x, collector.server.URL)
			liveHook(t, x, addon.ResponseHook{Flow: httpFlow(t)})
			g := currentGeneration(x)
			if err := x.c.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			assertJoined(t, g)
			if len(collector.spans()) != 1 {
				t.Fatal("Close lost a healthy queued flow")
			}
			select {
			case <-x.c.done:
			default:
				t.Fatal("controller worker not joined")
			}
		}},
		"reconfigure": {func(t *testing.T) {
			a, b := newOwnedCollector(t, false), newOwnedCollector(t, false)
			x := liveController(t, Config{}, nil)
			setEndpoint(t, x, a.server.URL)
			liveHook(t, x, addon.ResponseHook{Flow: httpFlow(t)})
			old := currentGeneration(x)
			setEndpoint(t, x, b.server.URL)
			assertJoined(t, old)
			liveHook(t, x, addon.ResponseHook{Flow: httpFlow(t)})
			if err := flushLive(t, x); err != nil {
				t.Fatal(err)
			}
			if len(a.spans()) != 1 || len(b.spans()) != 1 {
				t.Fatal("reconfiguration did not drain and route generations")
			}
		}},
		"rollback_stale": {func(t *testing.T) {
			a, b := newOwnedCollector(t, false), newOwnedCollector(t, false)
			x := liveController(t, Config{}, nil)
			setEndpoint(t, x, a.server.URL)
			if err := x.m.Addons.Add(t.Context(), &rejectingEndpoint{opts: x.m.Options, value: b.server.URL}); err != nil {
				t.Fatal(err)
			}
			err := x.m.Do(t.Context(), func(ctx context.Context) error {
				return x.m.Options.Update(ctx, map[string]any{endpointOption: b.server.URL})
			})
			if _, ok := errors.AsType[*options.OptionsError](err); !ok {
				t.Fatalf("rollback error=%v", err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
			defer cancel()
			if err := x.c.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			liveHook(t, x, addon.ResponseHook{Flow: httpFlow(t)})
			if err := flushLive(t, x); err != nil {
				t.Fatal(err)
			}
			if len(a.spans()) != 1 || len(b.spans()) != 0 {
				t.Fatal("rolled-back endpoint was published")
			}
		}},
	}
	t.Run("contracts", func(t *testing.T) {
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}
