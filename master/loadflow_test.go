// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package master_test

import (
	"context"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/master"
)

func TestLoadFlowReverse(t *testing.T) {
	tests := map[string]struct {
		modes  []string
		host   string
		port   int
		scheme string
		header string
	}{
		"success: reverse https":                {[]string{"reverse:https://other"}, "other", 443, "https", "other:443"},
		"success: reverse explicit port":        {[]string{"reverse:http://other:8080@9090"}, "other", 8080, "http", "other:8080"},
		"success: multiple modes keep original": {[]string{"reverse:https://other", "regular"}, "old", 80, "http", "old"},
		"success: regular keeps original":       {[]string{"regular"}, "old", 80, "http", "old"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := master.New(master.Config{})
			t.Cleanup(func() { _ = m.Close(t.Context()) })
			if err := m.Options.Update(t.Context(), map[string]any{"mode": tt.modes}); err != nil {
				t.Fatal(err)
			}
			f := testflow.TFlow()
			f.Request.Scheme = "http"
			f.Request.SetHost("old")
			f.Request.SetPort(80)
			f.Request.SetHostHeader("old")
			if err := m.LoadFlow(t.Context(), f); err != nil {
				t.Fatal(err)
			}
			got := []any{f.Request.Host, f.Request.Port, f.Request.Scheme, f.Request.Headers.Get("Host")}
			if diff := gocmp.Diff([]any{tt.host, tt.port, tt.scheme, tt.header}, got); diff != "" {
				t.Fatalf("retarget (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLoadFlowEvents(t *testing.T) {
	tests := map[string]struct {
		f    flow.Flow
		want []string
	}{
		"success: HTTP": {testflow.TFlow(testflow.WithResponse), []string{"requestheaders", "update", "request", "update", "responseheaders", "update", "response", "update"}},
		"success: TCP":  {testflow.TTCPFlow(), []string{"tcp_start", "update", "tcp_message", "update", "tcp_message", "update", "tcp_end", "update"}},
		"success: UDP":  {testflow.TUDPFlow(), []string{"udp_start", "update", "udp_message", "update", "udp_message", "update", "udp_end", "update"}},
		"success: DNS":  {testflow.TDNSFlow(testflow.WithResponse), []string{"dns_request", "update", "dns_response", "update"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := master.New(master.Config{})
			t.Cleanup(func() { _ = m.Close(t.Context()) })
			r := &addontest.Recorder{}
			if err := m.Addons.Add(t.Context(), r); err != nil {
				t.Fatal(err)
			}
			r.Reset()
			if err := m.LoadFlow(t.Context(), tt.f); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, r.Hooks()); diff != "" {
				t.Fatalf("hooks (-want +got):\n%s", diff)
			}
		})
	}
}

type loadingHandoff struct{ reached, resume chan struct{} }

func (h *loadingHandoff) Request(ctx context.Context, _ *flow.HTTPFlow) error {
	_, err := addon.Concurrent(ctx, func(context.Context) error {
		close(h.reached)
		<-h.resume
		return nil
	})
	return err
}

func TestLoadFlowConcurrentHandoff(t *testing.T) {
	m := master.New(master.Config{})
	t.Cleanup(func() { _ = m.Close(t.Context()) })
	h := &loadingHandoff{make(chan struct{}), make(chan struct{})}
	if err := m.Addons.Add(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- m.LoadFlow(t.Context(), testflow.TFlow()) }()
	startupSignal(t, h.reached)
	if err := m.Do(t.Context(), func(context.Context) error { close(h.resume); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := startupResult(t, result); err != nil {
		t.Fatal(err)
	}
}
