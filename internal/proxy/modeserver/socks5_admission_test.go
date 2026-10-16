// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
)

func TestSocks5ModeAdmission(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	tests := map[string]struct {
		spec       string
		listenHost string
		listenPort *int
		wantHost   string
		wantPort   int
		greeting   bool
	}{
		"default port":                            {spec: "socks5", wantPort: 1080},
		"fallback settings":                       {spec: "socks5", listenHost: "127.0.0.1", listenPort: new(12080), wantHost: "127.0.0.1", wantPort: 12080},
		"IPv6 listen settings":                    {spec: "socks5@[::1]:18080", wantHost: "::1", wantPort: 18080},
		"registered layer and listener lifecycle": {spec: "socks5@127.0.0.1:0", listenPort: new(12080), wantHost: "127.0.0.1", greeting: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, m, hooks := fixture(t)
			cfg.ListenHost, cfg.ListenPort = tt.listenHost, tt.listenPort
			mode, err := modespec.Parse(tt.spec)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := New(mode, cfg)
			if err != nil {
				t.Fatalf("SOCKS5 admission: %v", err)
			}
			t.Cleanup(func() { _ = instance.Stop() })
			if diff := gocmp.Diff(tt.spec, instance.Mode().String()); diff != "" {
				t.Fatalf("published mode (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(hookdata.LayerKind("socks5"), instance.top.Kind); diff != "" {
				t.Fatalf("top layer (-want +got):\n%s", diff)
			}
			if instance.host != tt.wantHost || instance.port != tt.wantPort {
				t.Fatalf("listen settings = %q:%d, want %q:%d", instance.host, instance.port, tt.wantHost, tt.wantPort)
			}
			if instance.IsRunning() || instance.LastError() != nil || len(instance.ListenAddrs()) != 0 {
				t.Fatal("configuration-only admission opened a listener or published an error")
			}
			if !tt.greeting {
				return
			}
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			address := instance.ListenAddrs()[0]
			client, err := new(net.Dialer).DialContext(t.Context(), "tcp", address.String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if got := await(t, hooks.connected); got != tt.spec {
				t.Fatalf("connected mode = %q, want %q", got, tt.spec)
			}
			if _, err := client.Write([]byte{5, 1, 0}); err != nil {
				t.Fatal(err)
			}
			var reply [2]byte
			if _, err := io.ReadFull(client, reply[:]); err != nil {
				t.Fatalf("registered SOCKS5 layer did not answer greeting: %v", err)
			}
			if diff := gocmp.Diff([]byte{5, 0}, reply[:]); diff != "" {
				t.Fatalf("no-auth method selection (-want +got):\n%s", diff)
			}
			if err := m.Do(t.Context(), func(context.Context) error { return instance.Stop() }); err != nil {
				t.Fatal(err)
			}
			if instance.IsRunning() || len(instance.ListenAddrs()) != 0 {
				t.Fatal("Stop retained a published listener")
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			await(t, hooks.disconnected)
			if client, err := new(net.Dialer).DialContext(t.Context(), "tcp", address.String()); err == nil {
				_ = client.Close()
				t.Fatal("stopped SOCKS5 listener accepted another client")
			}
		})
	}
}
