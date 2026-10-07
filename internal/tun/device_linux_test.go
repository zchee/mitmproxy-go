// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tun

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenSetupFailure(t *testing.T) {
	// rs:src/packet_sources/tun.rs:86 specifies the creation-error context.
	before := descriptorCount(t)
	dev, err := Open(strings.Repeat("x", unix.IFNAMSIZ), nil)
	if dev != nil {
		_ = dev.Close()
		t.Fatal("invalid interface name returned a device")
	}
	if err == nil || !strings.HasPrefix(err.Error(), "Failed to create TUN device:") {
		t.Fatalf("Open error = %v, want creation-error context", err)
	}
	if after := descriptorCount(t); after != before {
		t.Errorf("descriptor count after Open failure = %d, want %d", after, before)
	}
}
