// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"fmt"
	"net"
	"os"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestIsAddrInUse(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	duplicate, bindErr := net.Listen("tcp4", listener.Addr().String())
	if bindErr == nil {
		_ = duplicate.Close()
		t.Fatal("double bind unexpectedly succeeded")
	}
	tests := map[string]struct {
		err  error
		want bool
	}{
		"success: double bind":         {err: bindErr, want: true},
		"success: wrapped double bind": {err: fmt.Errorf("listen failed: %w", bindErr), want: true},
		"error: permission denied":     {err: os.ErrPermission},
		"error: closed listener":       {err: net.ErrClosed},
		"error: nil":                   {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, isAddrInUse(tt.err)); diff != "" {
				t.Fatalf("isAddrInUse(%v) mismatch (-want +got):\n%s", tt.err, diff)
			}
		})
	}
}
