// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package version

import "testing"

func TestString(t *testing.T) {
	if got, want := String(), "mitmproxy-go 0.1.0-dev"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
