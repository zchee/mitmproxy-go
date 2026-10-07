// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !windows

package local

import (
	"errors"
	"net"
	"testing"
)

func TestWindowsHostBoundary(t *testing.T) {
	tests := map[string]struct{ closeFirst bool }{
		"error: unsupported host does not acquire or elevate": {},
		"error: final close remains terminal":                 {closeFirst: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r := NewWindowsRedirector("", "missing-native-artifact")
			if test.closeFirst {
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
			}
			err := r.Launch(t.Context())
			if err == nil {
				t.Fatal("Windows launch succeeded on an unsupported host")
			}
			if test.closeFirst && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("closed Windows launch = %v", err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
