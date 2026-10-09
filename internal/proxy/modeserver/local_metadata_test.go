// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/local"
)

func TestLocalMetadataSnapshot(t *testing.T) {
	tests := map[string]struct {
		tunnel   *local.TunnelInfo
		expected map[string]any
	}{
		"optional native provenance": {tunnel: &local.TunnelInfo{Pid: new(uint32(42)), ProcessName: new("curl")}, expected: map[string]any{"pid": uint32(42), "process_name": "curl"}},
		"missing provenance":         {expected: map[string]any{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			info := localExtra(tt.tunnel)
			if tt.tunnel != nil {
				*tt.tunnel.Pid = 99
				*tt.tunnel.ProcessName = "changed"
			}
			stream := &localStream{info: info}
			for key, expected := range tt.expected {
				got, ok := stream.GetExtraInfo(key)
				if !ok || !gocmp.Equal(expected, got) {
					t.Fatalf("snapshot %s = %v, want %v", key, got, expected)
				}
			}
			if diff := gocmp.Diff(tt.expected, info); diff != "" {
				t.Fatal(diff)
			}
			if _, ok := stream.GetExtraInfo("unknown"); ok {
				t.Fatal("unknown metadata present")
			}
		})
	}
}
