// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package emoji_test

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/emoji"
)

func TestNamesOwnership(t *testing.T) {
	first := emoji.Names()
	want := slices.Clone(first)
	first[0] = "changed"
	if diff := cmp.Diff(want, emoji.Names()); diff != "" {
		t.Errorf("Names returned shared storage (-want +got):\n%s", diff)
	}
}

func TestTable(t *testing.T) {
	names := emoji.Names()
	if len(names) != 1843 {
		t.Errorf("Names() has %d entries, want 1843 as upstream's emoji.emoji", len(names))
	}

	tests := map[string]struct {
		name     string
		want     string
		wantOK   bool
		position int // index in Names, -1 to skip the order check
	}{
		"success: first entry":        {name: ":+1:", want: "\U0001f44d", wantOK: true, position: 0},
		"success: second entry":       {name: ":-1:", want: "\U0001f44e", wantOK: true, position: 1},
		"success: named circle":       {name: ":red_circle:", want: "\U0001f534", wantOK: true, position: -1},
		"success: plain character":    {name: "X", want: "X", wantOK: true, position: -1},
		"error: unknown shortcode":    {name: ":bogus:", position: -1},
		"error: bare word":            {name: "bogus", position: -1},
		"error: true is not a marker": {name: "true", position: -1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := emoji.Char(tt.name)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("Char(%q) = %q, %t; want %q, %t", tt.name, got, ok, tt.want, tt.wantOK)
			}
			if tt.position >= 0 && names[tt.position] != tt.name {
				t.Errorf("Names()[%d] = %q, want %q", tt.position, names[tt.position], tt.name)
			}
		})
	}

	for i, n := range names {
		if _, ok := emoji.Char(n); !ok {
			t.Fatalf("Names()[%d] = %q has no character", i, n)
		}
	}
}
