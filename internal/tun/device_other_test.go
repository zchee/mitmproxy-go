// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !linux

package tun

import "testing"

func TestOpenUnsupported(t *testing.T) {
	// rs:mitmproxy-rs/src/server/tun.rs:46-47,80-83 specifies this refusal.
	tests := map[string]struct{ name string }{
		"error: automatic interface": {},
		"error: named interface":     {name: "tun0"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dev, err := Open(tt.name, nil)
			if dev != nil {
				_ = dev.Close()
				t.Fatal("unsupported platform returned a device")
			}
			if err == nil || err.Error() != "TUN proxy mode is only supported on Linux" {
				t.Fatalf("Open error = %v, want exact Linux-only refusal", err)
			}
		})
	}
}
