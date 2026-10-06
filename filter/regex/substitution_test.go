// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package regex

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/google/go-cmp/cmp"
)

var substitutionRaceEnabled bool

func TestSubstitutionWorkingSet(t *testing.T) {
	p, err := CompilePattern("a", 0)
	if err != nil {
		t.Fatal(err)
	}
	subject := strings.Repeat("a", 1<<20)
	// Warm the engine pool before measuring the substitution itself.
	if _, err := p.SubString("b", "a", 0); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, allocated, retained runtime.MemStats
	runtime.ReadMemStats(&before)
	got, err := p.SubString("b", subject, 0)
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&allocated)
	runtime.GC()
	runtime.ReadMemStats(&retained)
	// Retained heap, including the output, must be less than 8 MiB.
	if retained.HeapAlloc > before.HeapAlloc+(8<<20) {
		t.Fatalf("retained heap grew by %d bytes; limit is 8 MiB", retained.HeapAlloc-before.HeapAlloc)
	}
	// This separate total-allocation guard detects an eager all-match table,
	// even when that table becomes garbage before the retained-heap sample.
	// Race instrumentation adds allocations to each engine call; the native
	// run enforces total allocation, while both runs enforce retained heap.
	if n := allocated.TotalAlloc - before.TotalAlloc; !substitutionRaceEnabled && n > 64<<20 {
		t.Fatalf("substitution allocated %d bytes; limit is 64 MiB", n)
	}
	if got != strings.Repeat("b", len(subject)) {
		t.Fatal("substitution did not replace every match")
	}
	runtime.KeepAlive(got)
	runtime.KeepAlive(subject)
}

func TestSubstitutionContext(t *testing.T) {
	tests := map[string]struct {
		pattern, subject, want string
		flags                  Flags
		count                  int
	}{
		"success: start anchor whole subject":   {pattern: `^a|b`, subject: "baaab", want: "xaaax"},
		"success: multiline anchors":            {pattern: `^a|b$`, subject: "ab\naab\n", want: "xx\nxax\n", flags: Multiline},
		"success: word boundaries":              {pattern: `\ba|b`, subject: "ba ab", want: "xa xx"},
		"success: captures across chunks":       {pattern: `(a)(b)?`, subject: strings.Repeat("ab", 5000) + "a", want: strings.Repeat("ba", 5000) + "a", count: 5000},
		"success: Latin1 offsets across chunks": {pattern: `.`, subject: strings.Repeat("\xff", 5000), want: strings.Repeat("x", 5000)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := CompilePattern(test.pattern, test.flags)
			if err != nil {
				t.Fatal(err)
			}
			replacement := "x"
			if strings.Contains(name, "captures") {
				replacement = `\2\1`
			}
			got, err := p.SubString(replacement, test.subject, test.count)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("substitution (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSubstitutionMatchBudget(t *testing.T) {
	tests := map[string]struct{ pattern, subject string }{
		"error: anchored match table":       {pattern: `\ba`, subject: strings.Repeat("a ", 1<<20)},
		"error: fallback aggregate matches": {pattern: `(?=a)a`, subject: strings.Repeat("a", (1<<20)+1)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := CompilePattern(test.pattern, 0)
			if err != nil {
				t.Fatal(err)
			}
			if p.bt != nil {
				// Measure match capacity independently of the fallback deadline.
				p.bt.MatchTimeout = regexp2.DefaultMatchTimeout
				p.nonempty.MatchTimeout = regexp2.DefaultMatchTimeout
			}
			out, err := p.SubString("", test.subject, 0)
			if out != "" || err == nil || err.Error() != "regex: too many matches" {
				t.Fatalf("output length=%d, error=%v; want no output and match-budget error", len(out), err)
			}
			capacity, ok := errors.AsType[*CapacityError](err)
			if !ok || capacity.Resource != "matches" {
				t.Fatalf("error=%v (%T); want matches CapacityError", err, err)
			}
			out, err = p.SubString("x", test.subject, 1)
			if err != nil || out == "" {
				t.Fatalf("limited substitution: length=%d, error=%v", len(out), err)
			}
		})
	}
}
