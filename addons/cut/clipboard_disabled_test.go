// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !clipboard

package cut

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

// TestClipboardDisabled ports test_cut_clip's data shapes and alert messages.
// The tagged transport uses the real desktop clipboard rather than a mock;
// unavailable backend error text belongs to that library, not pyperclip.
func TestClipboardDisabled(t *testing.T) {
	_, _, cmds := setup(t)
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	tests := map[string]struct {
		cuts command.CutSpec
		log  string
	}{
		"method":  {command.CutSpec{"request.method"}, "Clipped single cut."},
		"content": {command.CutSpec{"request.content"}, "Clipped single cut."},
		"csv":     {command.CutSpec{"request.method", "request.content"}, "Clipped 2 cuts as CSV."},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			logs.Reset()
			_, err := cmds.Call(t.Context(), "cut.clip", []flow.Flow{testflow.TFlow()}, tt.cuts)
			want := "cut.clip: clipboard support is not compiled in (build with -tags clipboard)"
			if err == nil || err.Error() != want {
				t.Fatalf("err=%v", err)
			}
			if !strings.Contains(logs.String(), tt.log) {
				t.Fatalf("log=%s", logs.String())
			}
		})
	}
}
