// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layer

import (
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestProtocolTimeouts(t *testing.T) {
	tests := map[string]struct {
		got  time.Duration
		want time.Duration
	}{
		"head deadline independent of idle":    {got: HeadReadTimeout, want: 30 * time.Second},
		"terminal cleanup independent of idle": {got: TerminalHookTimeout, want: 30 * time.Second},
		"UDP tuple idle expiry":                {got: UDPIdleTimeout, want: 20 * time.Second},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, tt.got); diff != "" {
				t.Fatalf("timeout (-want +got):\n%s", diff)
			}
		})
	}
}
