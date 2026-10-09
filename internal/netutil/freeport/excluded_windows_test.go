// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import "testing"

// TestWindowsExcludedRangesDiagnostic certifies native netsh output and access.
func TestWindowsExcludedRangesDiagnostic(t *testing.T) {
	ranges := excludedWindowsPorts()
	if ranges.err != nil {
		t.Fatalf("native excluded-range discovery: %v", ranges.err)
	}
	t.Logf("native Windows TCP excluded ranges: %v", ranges.tcp)
	t.Logf("native Windows UDP excluded ranges: %v", ranges.udp)
}
