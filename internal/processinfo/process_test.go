// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package processinfo

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestProcessGrouping(t *testing.T) {
	tests := map[string]struct {
		records []processRecord
		visible map[int32]struct{}
		want    []Process
	}{
		"empty": {want: []Process{}},
		"exact_paths_and_visibility": {
			records: []processRecord{
				{pid: 30, executable: "/apps/a", displayName: "later", isSystem: true},
				{pid: 20, executable: "/apps/a", displayName: "first"},
				{pid: 40, executable: "/apps/./a", displayName: "lexical"},
				{pid: 50},
				{pid: 10, executable: "/apps/b", isSystem: true},
			},
			visible: map[int32]struct{}{30: {}, 50: {}},
			want: []Process{
				{Executable: "/apps/./a", DisplayName: "lexical"},
				{Executable: "/apps/a", DisplayName: "first", IsVisible: true},
				{Executable: "/apps/b", DisplayName: "b", IsSystem: true},
			},
		},
		"visible_first_remains_visible": {
			records: []processRecord{{pid: 1, executable: "/a"}, {pid: 2, executable: "/a"}},
			visible: map[int32]struct{}{1: {}},
			want:    []Process{{Executable: "/a", DisplayName: "a", IsVisible: true}},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			before := slices.Clone(test.records)
			got := groupProcesses(test.records, test.visible)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("grouped processes (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(before, test.records, cmp.AllowUnexported(processRecord{})); diff != "" {
				t.Fatalf("input records mutated (-before +after):\n%s", diff)
			}
			if len(got) != 0 {
				got[0].DisplayName = "caller mutation"
				if diff := cmp.Diff(test.want, groupProcesses(test.records, test.visible)); diff != "" {
					t.Fatalf("results share caller state (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestProcessPlatformRules(t *testing.T) {
	t.Run("system_classification", func(t *testing.T) {
		tests := map[string]struct {
			platform string
			path     string
			uid      int64
			known    bool
			want     bool
		}{
			"darwin_system":     {platform: "darwin", path: "/System/Library/a", want: true},
			"darwin_boundary":   {platform: "darwin", path: "/Systematic/a"},
			"darwin_user":       {platform: "darwin", path: "/Applications/a"},
			"linux_root":        {platform: "linux", uid: 0, known: true, want: true},
			"linux_system":      {platform: "linux", uid: 999, known: true, want: true},
			"linux_user":        {platform: "linux", uid: 1000, known: true},
			"linux_unknown":     {platform: "linux", uid: 0},
			"linux_invalid":     {platform: "linux", uid: -1, known: true},
			"other_not_guessed": {platform: "freebsd", path: "/System/a", known: true},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				if got := systemProcess(test.platform, test.path, test.uid, test.known); got != test.want {
					t.Fatalf("systemProcess(%q, %q, %d, %t) = %t, want %t", test.platform, test.path, test.uid, test.known, got, test.want)
				}
			})
		}
	})
	t.Run("icon_sizing", func(t *testing.T) {
		tests := map[string]struct {
			width, height int
			wantW, wantH  int
			wantError     bool
		}{
			"square":    {width: 256, height: 256, wantW: 32, wantH: 32},
			"small":     {width: 1, height: 1, wantW: 32, wantH: 32},
			"landscape": {width: 64, height: 32, wantW: 32, wantH: 16},
			"portrait":  {width: 16, height: 64, wantW: 8, wantH: 32},
			"thin":      {width: 4096, height: 1, wantW: 32, wantH: 1},
			"maximum":   {width: 4096, height: 4096, wantW: 32, wantH: 32},
			"zero":      {height: 32, wantError: true},
			"negative":  {width: -1, height: 32, wantError: true},
			"oversized": {width: 4097, height: 32, wantError: true},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				w, h, err := iconSize(test.width, test.height)
				if (err != nil) != test.wantError || w != test.wantW || h != test.wantH {
					t.Fatalf("iconSize(%d, %d) = (%d, %d, %v), want (%d, %d), error %t", test.width, test.height, w, h, err, test.wantW, test.wantH, test.wantError)
				}
			})
		}
	})
	t.Run("native_buffer", func(t *testing.T) {
		tests := map[string]struct {
			width, height, stride int
			want                  int
			wantError             bool
		}{
			"padded":           {width: 2, height: 3, stride: 12, want: 36},
			"maximum":          {width: 4096, height: 4096, stride: 16384, want: maxNativeBytes},
			"short_row":        {width: 3, height: 2, stride: 8, wantError: true},
			"negative_stride":  {width: 1, height: 1, stride: -1, wantError: true},
			"aggregate_limit":  {width: 1, height: 2, stride: maxNativeBytes, wantError: true},
			"integer_overflow": {width: 1, height: 2, stride: int(^uint(0) >> 1), wantError: true},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				got, err := nativeBufferSize(test.width, test.height, test.stride)
				if got != test.want || (err != nil) != test.wantError {
					t.Fatalf("nativeBufferSize = %d, %v; want %d, error %t", got, err, test.want, test.wantError)
				}
			})
		}
	})
}
