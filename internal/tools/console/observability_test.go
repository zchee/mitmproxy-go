// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
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
				want := strings.Fields(`*core.Core *browser.Browser *block.Block *stripdnshttpsrecords.StripDNSHTTPSRecords *blocklist.BlockList *anticache.AntiCache *anticomp.AntiComp *clientplayback.ClientPlayback *commandhistory.Addon *comment.Comment *cut.Addon *disableh2c.DisableH2C *export.Addon *onboarding.Onboarding *proxyauth.ProxyAuth *proxyserver.ProxyServer *script.Loader *dnsresolver.DnsResolver *nextlayer.NextLayer *serverplayback.ServerPlayback *mapremote.MapRemote *maplocal.MapLocal *modifybody.ModifyBody *modifyheaders.ModifyHeaders *stickyauth.StickyAuth *stickycookie.StickyCookie *save.Save *savehar.Addon *tlsconfig.TLSConfig *upstreamauth.UpstreamAuth *updatealtsvc.UpdateAltSvc *intercept.Intercept *view.View *eventstore.EventStore *readfile.ReadFile *console.ConsoleAddon *keymap.Config *telemetry.Controller *errorcheck.ErrorCheck`)
				if diff := gocmp.Diff(want, got); diff != "" {
					t.Fatalf("addon order (-want +got):\n%s", diff)
				}
				if !m.Options.Has("otel_exporter_endpoint") || m.Options.Str("otel_exporter_endpoint") != "" {
					t.Fatal("exporter option is absent or enabled by default")
				}
			}},
			"defaults_no_io": {run: func(t *testing.T, m *Master) {
				var requests atomic.Int64
				collector := observabilityCollector(t, &requests)
				observabilityEndpoint(t, m, collector.URL)
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
				m.Shutdown()
				if err := m.Master.Run(t.Context()); err != nil {
					t.Fatalf("BeforeClose join: %v", err)
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
