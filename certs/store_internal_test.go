// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import "testing"

// TestStoreCap pins the default cap to upstream's CertStore.STORE_CAP.
func TestStoreCap(t *testing.T) {
	if storeCap != 100 {
		t.Errorf("storeCap = %d, want 100 as upstream's STORE_CAP", storeCap)
	}
}
