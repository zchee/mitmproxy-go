// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"fmt"
	"testing"
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
