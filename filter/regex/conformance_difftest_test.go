// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package regex

import (
	json "encoding/json/v2"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// conformanceModes are the ways a filter compiles a pattern, named as
// testdata/re_conformance.py names them: a text operator such as ~u with
// IGNORECASE, a bytes operator such as ~b with IGNORECASE and DOTALL, and
// both without IGNORECASE, as MITMPROXY_CASE_SENSITIVE_FILTERS has them.
var conformanceModes = map[string]Flags{
	"text":                 Unicode | IgnoreCase,
	"text-case-sensitive":  Unicode,
	"bytes":                IgnoreCase | DotAll,
	"bytes-case-sensitive": DotAll,
}

type pythonOutcome struct {
	Compiled bool   `json:"compiled"`
	Match    bool   `json:"match"`
	Error    string `json:"error"`
}

type conformanceCase struct {
	Pattern string                   `json:"pattern"`
	Subject string                   `json:"subject"`
	Results map[string]pythonOutcome `json:"results"`
}

// TestConformsToCPythonReTests runs every case of CPython's own regular
// expression test table, Lib/test/re_tests.py (testdata/cpython), through the pinned Python
// and through Compile in each mode a filter uses, and compares whether the
// pattern compiles and whether the subject matches. Every difference must
// be listed in knownDifferences with its reason, and every listed
// difference must still occur, so that a new difference, or a fixed one,
// fails the test.
func TestConformsToCPythonReTests(t *testing.T) {
	out := difftest.Script(t, filepath.Join("testdata", "re_conformance.py"), testutil.FixturePath(t, "cpython/re_tests.py"))
	var oracle struct {
		Python string            `json:"python"`
		Cases  []conformanceCase `json:"cases"`
	}
	if err := json.Unmarshal(out, &oracle); err != nil {
		t.Fatalf("decode oracle output: %v", err)
	}
	var timeouts atomic.Int64
	SetLogger(func(string, error) { timeouts.Add(1) })
	t.Cleanup(func() { SetLogger(nil) })

	var (
		runs, agree int
		seen        = map[string]bool{}
		unexplained []string
	)
	for _, c := range oracle.Cases {
		for mode, flags := range conformanceModes {
			want, ok := c.Results[mode]
			if !ok {
				t.Fatalf("oracle has no %s result for %q", mode, c.Pattern)
			}
			runs++
			before := timeouts.Load()
			got := pythonOutcome{}
			m, err := Compile(c.Pattern, flags)
			if err == nil {
				got.Compiled = true
				if flags&Unicode != 0 {
					got.Match = m.MatchString(c.Subject)
				} else {
					got.Match = m.Match([]byte(c.Subject))
				}
			} else {
				got.Error = err.Error()
			}
			timedOut := timeouts.Load() != before
			if got.Compiled == want.Compiled && (!got.Compiled || got.Match == want.Match) && !timedOut {
				agree++
				continue
			}
			if d, ok := knownDifferences[c.Pattern]; ok && (d.modes == nil || slices.Contains(d.modes, mode)) {
				seen[c.Pattern] = true
				continue
			}
			unexplained = append(unexplained, fmt.Sprintf("%-20s %q on %q: python %s, go %s", mode, c.Pattern, c.Subject, describe(want, false), describe(got, timedOut)))
		}
	}
	t.Logf("Python %s: %d runs of %d cases, %d agree, %d known differences in %d of the %d listed patterns", oracle.Python, runs, len(oracle.Cases), agree, runs-agree-len(unexplained), len(seen), len(knownDifferences))
	slices.Sort(unexplained)
	if len(unexplained) > 0 {
		t.Errorf("%d results differ from Python and are not in knownDifferences:\n%s", len(unexplained), strings.Join(unexplained, "\n"))
	}
	for pattern := range knownDifferences {
		if !seen[pattern] {
			t.Errorf("knownDifferences lists %q, which now behaves as in Python; remove it", pattern)
		}
	}
}

func describe(o pythonOutcome, timedOut bool) string {
	switch {
	case timedOut:
		return "timed out"
	case !o.Compiled:
		return "error (" + o.Error + ")"
	case o.Match:
		return "match"
	}
	return "no match"
}

// knownDifference is a case of the table that differs from Python on
// purpose or by a documented limit, in the listed modes or, when modes is
// nil, in every mode.
type knownDifference struct {
	modes  []string
	reason string
}

// knownDifferences lists, by pattern, the cases of the table where Compile
// differs from Python, each with the docs/compat.md row that explains it.
var knownDifferences = map[string]knownDifference{
	// A bytes pattern sees the input as Latin-1 bytes, so \xff is the byte
	// 0xff and does not occur in the UTF-8 encoding of U+00FF; both Go
	// engines decode UTF-8 and match the character. docs/compat.md: "Byte
	// patterns (~b, ~h, ~m, ...) see the input as Latin-1 bytes".
	`\xff`: {modes: []string{"bytes", "bytes-case-sensitive"}, reason: "bytes patterns read Latin-1, the Go engines UTF-8"},
}
