// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/internal/debugserver"
	"github.com/zchee/mitmproxy-go/internal/telemetry"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func TestObservabilityAssembly(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T, *Master) }{
			"registered": {run: func(t *testing.T, m *Master) {
				if got, ok := m.Addons.Get("telemetry").(*telemetry.Controller); !ok || got != m.telemetry {
					t.Fatal("default set does not own the configured telemetry controller")
				}
				var got []string
				for _, a := range m.Addons.Chain() {
					got = append(got, fmt.Sprintf("%T", a))
				}
				want := strings.Fields(`*core.Core *browser.Browser *block.Block *stripdnshttpsrecords.StripDNSHTTPSRecords *blocklist.BlockList *anticache.AntiCache *anticomp.AntiComp *clientplayback.ClientPlayback *commandhistory.Addon *comment.Comment *cut.Addon *disableh2c.DisableH2C *export.Addon *onboarding.Onboarding *proxyauth.ProxyAuth *proxyserver.ProxyServer *script.Loader *dnsresolver.DnsResolver *nextlayer.NextLayer *serverplayback.ServerPlayback *mapremote.MapRemote *maplocal.MapLocal *modifybody.ModifyBody *modifyheaders.ModifyHeaders *stickyauth.StickyAuth *stickycookie.StickyCookie *save.Save *savehar.Addon *tlsconfig.TLSConfig *upstreamauth.UpstreamAuth *updatealtsvc.UpdateAltSvc *intercept.Intercept *view.View *eventstore.EventStore *readfile.ReadFile *console.ConsoleAddon *keymap.Config *telemetry.Controller *debugserver.Controller *errorcheck.ErrorCheck`)
				if diff := gocmp.Diff(want, got); diff != "" {
					t.Fatalf("addon order (-want +got):\n%s", diff)
				}
				if got, ok := m.Addons.Get("debugserver").(*debugserver.Controller); !ok || got != m.debug {
					t.Fatal("default set does not own the configured diagnostics controller")
				}
				if !m.Options.Has("pprof_addr") || m.Options.Str("pprof_addr") != "" {
					t.Fatal("diagnostics option is absent or enabled by default")
				}
				if !m.Options.Has("otel_exporter_endpoint") || m.Options.Str("otel_exporter_endpoint") != "" {
					t.Fatal("exporter option is absent or enabled by default")
				}
			}},
			"defaults_no_io": {run: func(t *testing.T, m *Master) {
				var requests atomic.Int64
				collector := observabilityCollector(t, &requests)
				observabilityEndpoint(t, m, collector.URL)
				observabilityDebugAddress(t, m, "127.0.0.1:0")
				if status := m.debug.Status(); status.Enabled || status.Address != "" {
					t.Fatalf("metadata construction bound diagnostics: %+v", status)
				}
				if err := m.telemetry.Sync(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := m.Close(t.Context()); err != nil {
					t.Fatal(err)
				}
				if m.telemetry.Status().Enabled || requests.Load() != 0 {
					t.Fatal("metadata-only construction opened the exporter")
				}
			}},
			"reconfigure": {run: func(t *testing.T, m *Master) {
				var requests atomic.Int64
				a, b := observabilityCollector(t, &requests), observabilityCollector(t, &requests)
				if err := m.telemetry.Running(t.Context()); err != nil {
					t.Fatal(err)
				}
				for _, endpoint := range []string{a.URL, b.URL, ""} {
					observabilityEndpoint(t, m, endpoint)
					if err := m.telemetry.Sync(t.Context()); err != nil {
						t.Fatal(err)
					}
					if got := m.telemetry.Status().Enabled; got != (endpoint != "") {
						t.Fatalf("settled exporter enabled = %t for endpoint %q", got, endpoint)
					}
				}
				if err := m.debug.Running(t.Context()); err != nil {
					t.Fatal(err)
				}
				observabilityDebugAddress(t, m, "127.0.0.1:0")
				bound := m.debug.Status()
				if !bound.Enabled || bound.Address == "" || bound.Requested != "127.0.0.1:0" {
					t.Fatalf("diagnostics did not bind: %+v", bound)
				}
				client := &http.Client{Transport: &http.Transport{}}
				defer client.CloseIdleConnections()
				for _, path := range []string{"/debug", "/debug/pprof/"} {
					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+bound.Address+path, nil)
					if err != nil {
						t.Fatal(err)
					}
					response, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					data, readErr := io.ReadAll(response.Body)
					closeErr := response.Body.Close()
					if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK {
						t.Fatalf("%s response: status=%d read=%v close=%v", path, response.StatusCode, readErr, closeErr)
					}
					if path == "/debug" {
						var document struct {
							Runtime     []any              `json:"runtime"`
							Telemetry   telemetry.Status   `json:"telemetry"`
							Diagnostics debugserver.Status `json:"diagnostics"`
						}
						if err := json.Unmarshal(data, &document); err != nil {
							t.Fatal(err)
						}
						if len(document.Runtime) == 0 || document.Diagnostics.Address != bound.Address {
							t.Fatalf("wrong diagnostics document: %+v", document.Diagnostics)
						}
						if diff := gocmp.Diff(m.telemetry.Status(), document.Telemetry); diff != "" {
							t.Fatalf("instance counters (-want +got):\n%s", diff)
						}
					}
				}
				failures := m.telemetry.Status().ExportFailures
				observabilityEndpoint(t, m, "http://"+bound.Address)
				if err := m.telemetry.Sync(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := m.Addons.Hook(t.Context(), addon.ResponseHook{Flow: testflow.TFlow(testflow.WithResponse)}); err != nil {
					t.Fatal(err)
				}
				observabilityEndpoint(t, m, "")
				if err := m.telemetry.Sync(t.Context()); err != nil {
					t.Fatal(err)
				}
				if got := m.telemetry.Status().ExportFailures; got <= failures {
					t.Fatal("self-listener export was not recorded as refused")
				}
				observabilityDebugAddress(t, m, "localhost:0")
				rebound := m.debug.Status()
				if !rebound.Enabled || rebound.Requested != "localhost:0" {
					t.Fatalf("diagnostics rebind did not settle: %+v", rebound)
				}
				observabilityDebugAddress(t, m, "")
				if disabled := m.debug.Status(); disabled.Enabled || disabled.Address != "" {
					t.Fatalf("diagnostics disable did not join: %+v", disabled)
				}
			}},
			"close_join": {run: func(t *testing.T, m *Master) {
				var requests atomic.Int64
				collector := observabilityCollector(t, &requests)
				observabilityEndpoint(t, m, collector.URL)
				if err := m.telemetry.Running(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := m.telemetry.Sync(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := m.Addons.Hook(t.Context(), addon.RequestHook{Flow: testflow.TFlow()}); err != nil {
					t.Fatal(err)
				}
				if got := m.telemetry.Status().ActiveFlows; got != 1 {
					t.Fatalf("callback did not observe active flow: %d", got)
				}
				if err := m.debug.Running(t.Context()); err != nil {
					t.Fatal(err)
				}
				observabilityDebugAddress(t, m, "127.0.0.1:0")
				conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", m.debug.Status().Address)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = conn.Close() }()
				if _, err := conn.Write([]byte("GET /debug HTTP/1.1\r\n")); err != nil {
					t.Fatal(err)
				}
				started := time.Now()
				m.Shutdown()
				if err := m.Master.Run(t.Context()); err != nil {
					t.Fatalf("BeforeClose join: %v", err)
				}
				if elapsed := time.Since(started); elapsed > 10*time.Second {
					t.Fatalf("observability Close exceeded the shared deadline: %v", elapsed)
				}
				if status := m.debug.Status(); !status.Stopped || status.Enabled || status.Address != "" {
					t.Fatalf("diagnostics did not join: %+v", status)
				}
				if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				var data [1]byte
				if _, err := conn.Read(data[:]); err == nil {
					t.Fatal("diagnostics connection stayed open after join")
				} else if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
					t.Fatalf("diagnostics connection did not acknowledge closure: %v", err)
				}
				if got := m.telemetry.Status(); !got.Stopped || got.ActiveFlows != 0 || got.Enabled || requests.Load() == 0 {
					t.Fatalf("Close did not flush and join active telemetry: %+v, exports=%d", got, requests.Load())
				}
				if err := m.Close(t.Context()); err != nil {
					t.Fatalf("repeated Close: %v", err)
				}
			}},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				opts := options.New()
				if err := opts.Update(t.Context(), map[string]any{"confdir": t.TempDir(), "server": false}); err != nil {
					t.Fatal(err)
				}
				m, err := New(t.Context(), Config{Options: opts, Stdout: io.Discard, Stderr: io.Discard})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
						t.Error(err)
					}
				})
				tt.run(t, m)
			})
		}
	})
}

func observabilityEndpoint(t *testing.T, m *Master, endpoint string) {
	t.Helper()
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		return m.Options.Update(ctx, map[string]any{"otel_exporter_endpoint": endpoint})
	}); err != nil {
		t.Fatal(err)
	}
}

func observabilityDebugAddress(t *testing.T, m *Master, address string) {
	t.Helper()
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		return m.Options.Update(ctx, map[string]any{"pprof_addr": address})
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.debug.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func observabilityCollector(t *testing.T, requests *atomic.Int64) *httptest.Server {
	t.Helper()
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		requests.Add(1)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)
	return collector
}
