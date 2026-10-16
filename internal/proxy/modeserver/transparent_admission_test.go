// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
)

func TestTransparentModeAdmission(t *testing.T) {
	tests := map[string]struct {
		spec       string
		listenHost string
		listenPort *int
		wantHost   string
		wantPort   int
	}{
		"default port":             {spec: "transparent", wantPort: 8080},
		"fallback settings":        {spec: "transparent", listenHost: "127.0.0.1", listenPort: new(12080), wantHost: "127.0.0.1", wantPort: 12080},
		"explicit listen settings": {spec: "transparent@127.0.0.1:0", listenPort: new(12080), wantHost: "127.0.0.1"},
		"IPv6 listen settings":     {spec: "transparent@[::1]:18080", wantHost: "::1", wantPort: 18080},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			cfg.ListenHost, cfg.ListenPort = tt.listenHost, tt.listenPort
			mode, err := modespec.Parse(tt.spec)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := New(mode, cfg)
			if err != nil {
				t.Fatalf("transparent admission: %v", err)
			}
			if diff := gocmp.Diff(tt.spec, instance.Mode().String()); diff != "" {
				t.Fatalf("published mode (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(hookdata.LayerKind("transparent"), instance.top.Kind); diff != "" {
				t.Fatalf("top layer (-want +got):\n%s", diff)
			}
			if instance.host != tt.wantHost || instance.port != tt.wantPort {
				t.Fatalf("listen settings = %q:%d, want %q:%d", instance.host, instance.port, tt.wantHost, tt.wantPort)
			}
			if instance.IsRunning() || instance.LastError() != nil || len(instance.ListenAddrs()) != 0 {
				t.Fatal("configuration-only admission opened a listener or published an error")
			}
		})
	}
}
