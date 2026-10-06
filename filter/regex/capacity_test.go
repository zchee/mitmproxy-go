// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package regex

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSubstitutionCaptureTableScope(t *testing.T) {
	groups := maxMatchBytes / 32
	body := strings.Repeat("()", groups) + "a"
	tests := map[string]struct {
		pattern string
		want    string
		limited bool
	}{
		"success: anchor-free captures retain one match": {pattern: body, want: "xx"},
		"error: anchored captures require bounded table": {pattern: "^" + body, limited: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := CompilePattern(test.pattern, 0)
			if err != nil {
				t.Fatal(err)
			}
			if p.re == nil {
				t.Fatal("capture-table case must use RE2")
			}
			got, err := p.SubString("x", "aa", 0)
			if test.limited {
				if got != "" || err == nil || err.Error() != "regex: capture table exceeds working-memory budget" {
					t.Fatalf("output length=%d, error=%v; want no output and capture-table limit", len(got), err)
				}
				capacity, ok := errors.AsType[*CapacityError](err)
				if !ok || capacity.Resource != "capture table" || capacity.Limit != maxMatchBytes {
					t.Fatalf("error=%v (%T); want capture-table CapacityError", err, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("substitution (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPatternCapacityError(t *testing.T) {
	p, err := CompilePattern("a", 0)
	if err != nil {
		t.Fatal(err)
	}
	oversized := strings.Repeat("a", maxSubBytes+1)
	tests := map[string]struct {
		run      func() error
		resource string
		limit    int
	}{
		"error: pattern":        {run: func() error { _, err := CompilePattern(strings.Repeat("a", maxPatternBytes+1), 0); return err }, resource: "pattern", limit: maxPatternBytes},
		"error: string subject": {run: func() error { _, err := p.SearchString(oversized); return err }, resource: "subject", limit: maxSubBytes},
		"error: byte subject":   {run: func() error { _, err := p.Search([]byte(oversized)); return err }, resource: "subject", limit: maxSubBytes},
		"error: replacement":    {run: func() error { _, err := p.SubString(oversized, "a", 0); return err }, resource: "replacement", limit: maxSubBytes},
		"error: output": {run: func() error {
			var b strings.Builder
			b.WriteByte('a')
			return appendBounded(&b, oversized[:maxSubBytes])
		}, resource: "substituted output", limit: maxSubBytes},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.run()
			capacity, ok := errors.AsType[*CapacityError](err)
			if !ok {
				t.Fatalf("error=%v (%T); want *CapacityError", err, err)
			}
			if capacity.Resource != test.resource || capacity.Limit != test.limit {
				t.Fatalf("capacity=%+v; want resource=%q limit=%d", capacity, test.resource, test.limit)
			}
		})
	}
}
