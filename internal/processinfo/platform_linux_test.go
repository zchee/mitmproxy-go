// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build linux

package processinfo

import (
	"errors"
	"testing"
)

func TestProcessLinuxRules(t *testing.T) {
	visible, err := visibleProcessIDs()
	if err != nil || len(visible) != 0 {
		t.Fatalf("Linux visibility = %v, %v; want empty", visible, err)
	}
	data, err := ExecutableIcon("/does/not/exist")
	unsupported, ok := errors.AsType[*UnsupportedError](err)
	if !ok || unsupported.Platform != "linux" || data != nil {
		t.Fatalf("Linux icon = %v, %v; want typed unsupported", data, err)
	}
}
