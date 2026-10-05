// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !clipboard

package export

import (
	"testing"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestClipboardDisabled(t *testing.T) {
	_, _, cmds := setup(t)
	tests := map[string]struct{ format string }{"curl": {"curl"}, "httpie": {"httpie"}, "raw": {"raw"}, "request": {"raw_request"}, "response": {"raw_response"}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := cmds.Call(t.Context(), "export.clip", tt.format, flow.Flow(testflow.TFlow(testflow.WithResponse)))
			want := "export.clip: clipboard support is not compiled in (build with -tags clipboard)"
			if err == nil || err.Error() != want {
				t.Fatalf("error=%v, want %q", err, want)
			}
		})
	}
}
