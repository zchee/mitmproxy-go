// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package spec

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

// TestParse ports test_parse_spec from mitmproxy/utils/test_spec.py.
func TestParse(t *testing.T) {
	tests := map[string]struct {
		option      string
		pattern     string
		subject     string
		replacement string
		err         string
		filterError bool
	}{
		"error: empty":                           {option: "", err: "Invalid number of parameters (2 or 3 are expected)"},
		"error: missing parameters":              {option: "/", err: "Invalid number of parameters (2 or 3 are expected)"},
		"error: missing replacement":             {option: "/foo", err: "Invalid number of parameters (2 or 3 are expected)"},
		"error: invalid filter":                  {option: "/~b/one/two", err: "invalid filter expression", filterError: true},
		"error: empty filter":                    {option: "//one/two", err: "empty filter expression", filterError: true},
		"success: filtered":                      {option: "/foo/bar/voing", pattern: "~u foo", subject: "bar", replacement: "voing"},
		"success: match all":                     {option: "/bar/voing", pattern: "~all", subject: "bar", replacement: "voing"},
		"success: separator in replacement":      {option: "/foo/bar/voing/more", pattern: "~u foo", subject: "bar", replacement: "voing/more"},
		"success: empty subject and replacement": {option: "//", pattern: "~all"},
		"success: alternate separator":           {option: "|~q|foo|bar", pattern: "~q", subject: "foo", replacement: "bar"},
		"success: unicode separator":             {option: "界foo界bar", pattern: "~all", subject: "foo", replacement: "bar"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			expr, subject, replacement, err := Parse(tt.option)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("Parse(%q) error = %v; want %q", tt.option, err, tt.err)
				}
				if tt.filterError {
					if _, ok := errors.AsType[*filter.ParseError](err); !ok {
						t.Fatalf("error type = %T; want *filter.ParseError", err)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff([]string{tt.pattern, tt.subject, tt.replacement}, []string{expr.String(), subject, replacement}); diff != "" {
				t.Fatalf("Parse(%q) (-want +got):\n%s", tt.option, diff)
			}
			if tt.pattern == "~all" && !filter.Match(expr, testflow.TFlow()) {
				t.Fatal("two-part spec did not match all flows")
			}
		})
	}
}
