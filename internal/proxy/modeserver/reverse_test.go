// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"fmt"
	"testing"

	"github.com/zchee/mitmproxy-go/connection"
)

func TestReverseProtocolAdmission(t *testing.T) {
	cfg, _, _ := fixture(t)
	tests := map[string]struct{ scheme string }{
		"DNS":    {"dns"},
		"QUIC":   {"quic"},
		"HTTP/3": {"http3"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			instance := makeInstance(t, "reverse:"+tt.scheme+"://example.test:443@127.0.0.1:0", cfg)
			if tt.scheme == "dns" {
				if err := instance.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				if !instance.IsRunning() || len(instance.ListenAddrs()) != 2 {
					t.Fatal("DNS did not publish its TCP and UDP listeners")
				}
				return
			}
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal("registered protocol start:", err)
			}
			addresses := instance.ListenAddrs()
			if !instance.IsRunning() || instance.LastError() != nil || len(addresses) != 1 || addresses[0].Host != "127.0.0.1" || addresses[0].Port == 0 {
				t.Fatalf("registered protocol listener was not published: %v", addresses)
			}
			if err := instance.Stop(); err != nil {
				t.Fatal("registered protocol stop:", err)
			}
			if instance.IsRunning() || instance.LastError() != nil || len(instance.ListenAddrs()) != 0 {
				t.Fatal("registered protocol did not stop cleanly")
			}
			// Remove only this instance's snapshot to exercise missing-factory
			// admission without changing process-wide protocol registrations.
			delete(instance.factories, ListenerKey{Scheme: tt.scheme, Transport: connection.UDP})
			want := fmt.Sprintf("modeserver: reverse scheme %q is not implemented yet", tt.scheme)
			if err := instance.Start(t.Context()); err == nil || err.Error() != want {
				t.Fatalf("Start = %v, want %q", err, want)
			}
			if instance.IsRunning() || len(instance.ListenAddrs()) != 0 || instance.LastError() == nil {
				t.Fatal("unsupported protocol published listeners or lost its start error")
			}
		})
	}
}
