// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package textwrap

import (
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// The expected values below were produced by CPython's textwrap module.

func TestDedent(t *testing.T) {
	tests := map[string]struct {
		in   string
		want string
	}{
		"success: common margin removed":        {in: "\n    a\n      b\n    c\n", want: "\na\n  b\nc\n"},
		"success: unindented first line":        {in: "x\n    y", want: "x\n    y"},
		"success: spaces and tab share nothing": {in: "  a\n\tb", want: "  a\n\tb"},
		"success: whitespace-only line emptied": {in: "  a\n  \n  b", want: "a\n\nb"},
		"success: tab margin":                   {in: "\n\t\ta\n\t\tb", want: "\na\nb"},
		"success: single line":                  {in: "a", want: "a"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Dedent(tt.in); got != tt.want {
				t.Errorf("Dedent(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestWrap(t *testing.T) {
	tests := map[string]struct {
		in   string
		want []string
	}{
		"success: leading double hyphen stays whole": {
			in:   "Opposite of --ignore-hosts. Type sequence of str.",
			want: []string{"Opposite of --ignore-hosts. Type sequence of str."},
		},
		"success: hyphenated word moves whole when the first part does not fit": {
			in: "Path to a .proto file that's used to resolve Protobuf field names when pretty-printing. Type optional str.",
			want: []string{
				"Path to a .proto file that's used to resolve Protobuf field names when",
				"pretty-printing. Type optional str.",
			},
		},
		"success: break after hyphen": {
			in:   strings.Repeat("aaaa ", 13) + "mode-specific word",
			want: []string{"aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa mode-", "specific word"},
		},
		"success: long word broken at width": {
			in:   strings.Repeat("x", 75),
			want: []string{strings.Repeat("x", 70), "xxxxx"},
		},
		"success: long word on its own line": {
			in:   "abc " + strings.Repeat("y", 70),
			want: []string{"abc", strings.Repeat("y", 70)},
		},
		"success: em-dashes and hyphens": {
			in:   "short-lived well-known --flag a--b em--dash, word--word",
			want: []string{"short-lived well-known --flag a--b em--dash, word--word"},
		},
		"success: multi-hyphen word": {
			in:   strings.Repeat("a", 60) + " pretty-printing-in-long-words",
			want: []string{strings.Repeat("a", 60) + " pretty-", "printing-in-long-words"},
		},
		"success: inner space runs kept": {
			in:   "lead   spaces    inside     a  line that is long enough to need wrapping across two lines ok",
			want: []string{"lead   spaces    inside     a  line that is long enough to need", "wrapping across two lines ok"},
		},
		"success: tab expanded": {
			in:   "tab\there",
			want: []string{"tab     here"},
		},
		"success: long hyphenated word": {
			in:   "foo-" + strings.Repeat("b", 80),
			want: []string{"foo-" + strings.Repeat("b", 66), strings.Repeat("b", 14)},
		},
		"success: empty":      {in: "", want: nil},
		"success: blank only": {in: "   ", want: nil},
		"success: non-ascii letters": {
			in:   strings.Repeat("naïve café-au-lait résumé ", 3),
			want: []string{"naïve café-au-lait résumé naïve café-au-lait résumé naïve café-au-lait", "résumé"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, Wrap(tt.in), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Wrap(%q) mismatch (-want +got):\n%s", tt.in, diff)
			}
		})
	}
}
