// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package regex

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestPatternSub(t *testing.T) {
	tests := map[string]struct {
		pattern, replacement, subject, want string
		flags                               Flags
		count                               int
	}{
		"success: RE2 numbered captures":                     {pattern: `(a)(b)`, replacement: `\2\1-$`, subject: "abab", want: "ba-$ba-$"},
		"success: named captures and whole match":            {pattern: `(?P<first>a)(b)`, replacement: `\g<2>\g<first>\g<0>`, subject: "ab", want: "baab"},
		"success: fallback preserves Python numbering":       {pattern: `(?P<first>a)(b)(?P=first)`, replacement: `\1\2\g<first>`, subject: "aba", want: "aba"},
		"success: fallback numeric reference to named group": {pattern: `(?P<first>a)(b)\1`, replacement: `\2\1`, subject: "aba", want: "ba"},
		"success: fallback conditional named group":          {pattern: `(?P<first>a)?(?(first)b|c)`, replacement: `\g<first>!`, subject: "ab c", want: "a! !"},
		"success: unmatched group becomes empty":             {pattern: `(a)?b`, replacement: `<\1>`, subject: "b ab", want: "<> <a>"},
		"success: final newline is not consumed":             {pattern: `(?P<value>a)$`, replacement: `<\1>`, subject: "a\n", want: "<a>\n"},
		"success: empty following nonempty":                  {pattern: `x*`, replacement: "-", subject: "abxd", want: "-a-b--d-"},
		"success: nonempty following empty at same position": {pattern: `|a`, replacement: "-", subject: "a", want: "---"},
		"success: lazy captures":                             {pattern: `(.*?)`, replacement: `[\1]`, subject: "ab", want: "[][a][][b][]"},
		"success: lookahead":                                 {pattern: `(?=a)`, replacement: "-", subject: "aa", want: "-a-a"},
		"success: anchors retain original input":             {pattern: `^a`, replacement: "-", subject: "aaa", want: "-aa"},
		"success: count limits replacements":                 {pattern: `a`, replacement: "x", subject: "aaa", count: 2, want: "xxa"},
		"success: negative count replaces nothing":           {pattern: `a`, replacement: "x", subject: "aaa", count: -1, want: "aaa"},
		"success: template escapes":                          {pattern: `a`, replacement: `\a\b\f\n\r\t\v\\\&\101\0`, subject: "a", want: "\a\b\f\n\r\t\v\\\\&A\x00"},
		"success: Unicode string groups":                     {pattern: `(?P<word>\w+)`, replacement: `[\g<word>]`, subject: "é 世", flags: Unicode, want: "[é] [世]"},
		"success: bytes preserve invalid UTF8":               {pattern: `.`, replacement: "x", subject: "\xff\xc3\xa9", want: "xxx"},
		"success: bytes literal high byte":                   {pattern: "\xff", replacement: "y", subject: "\xff\xfe", want: "y\xfe"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			pattern, err := CompilePattern(test.pattern, test.flags)
			if err != nil {
				t.Fatal(err)
			}
			got, err := pattern.SubString(test.replacement, test.subject, test.count)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("substitution (-want +got):\n%s", diff)
			}
			bytes, err := pattern.Sub([]byte(test.replacement), []byte(test.subject), test.count)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(test.want, string(bytes)); diff != "" {
				t.Fatalf("byte substitution (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPatternSearch(t *testing.T) {
	tests := map[string]struct {
		pattern, subject string
		flags            Flags
		groups           []string
		spans            [][2]int
	}{
		"success: named and unnamed numbering":   {pattern: `(?P<first>a)(b)(?P=first)`, subject: "xaba", groups: []string{"aba", "a", "b"}, spans: [][2]int{{1, 4}, {1, 2}, {2, 3}}},
		"success: Unicode byte offsets":          {pattern: `(世)(é)`, subject: "a世é", flags: Unicode, groups: []string{"世é", "世", "é"}, spans: [][2]int{{1, 6}, {1, 4}, {4, 6}}},
		"success: fallback Unicode byte offsets": {pattern: `(?<=a)(世)(é)`, subject: "a世é", flags: Unicode, groups: []string{"世é", "世", "é"}, spans: [][2]int{{1, 6}, {1, 4}, {4, 6}}},
		"success: absent optional group":         {pattern: `(a)?b`, subject: "b", groups: []string{"b", ""}, spans: [][2]int{{0, 1}, {-1, -1}}},
		"success: dollar excludes final newline": {pattern: `(a)$`, subject: "a\n", groups: []string{"a", "a"}, spans: [][2]int{{0, 1}, {0, 1}}},
		"success: bytes are Latin1":              {pattern: `(.)`, subject: "\xff\xfe", groups: []string{"\xff", "\xff"}, spans: [][2]int{{0, 1}, {0, 1}}},
		"success: no match":                      {pattern: `a`, subject: "z"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			pattern, err := CompilePattern(test.pattern, test.flags)
			if err != nil {
				t.Fatal(err)
			}
			got, err := pattern.SearchString(test.subject)
			if err != nil {
				t.Fatal(err)
			}
			var want *Match
			if test.groups != nil {
				want = &Match{Groups: test.groups, Spans: test.spans}
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Fatalf("search (-want +got):\n%s", diff)
			}
			if pattern.MatchString(test.subject) != (want != nil) || pattern.Match([]byte(test.subject)) != (want != nil) {
				t.Fatal("Matcher disagrees with Search")
			}
		})
	}
}

func TestPatternInvalid(t *testing.T) {
	tests := map[string]struct{ pattern, replacement string }{
		"error: unterminated group":    {pattern: "("},
		"error: nonexistent number":    {pattern: "a", replacement: `\1`},
		"error: nonexistent name":      {pattern: "a", replacement: `\g<missing>`},
		"error: incomplete group name": {pattern: "a", replacement: `\g<foo`},
		"error: bad escape":            {pattern: "a", replacement: `\q`},
		"error: trailing backslash":    {pattern: "a", replacement: `\`},
		"error: octal overflow":        {pattern: "a", replacement: `\400`},
		"error: oversized pattern":     {pattern: strings.Repeat("a", (1<<20)+1)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := CompilePattern(test.pattern, 0)
			if err == nil {
				_, err = p.SubString(test.replacement, "no match", 0)
			}
			if err == nil {
				t.Fatal("invalid pattern or replacement accepted")
			}
		})
	}
}

func TestPatternConcurrent(t *testing.T) {
	p, err := CompilePattern(`(?P<letter>a)(b)(?P=letter)`, 0)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				got, err := p.SubString(`\2\1`, "aba aba", 0)
				if err != nil || got != "ba ba" {
					t.Errorf("concurrent substitution = %q, %v", got, err)
					return
				}
			}
		})
	}
	wg.Wait()
}

func TestPatternLimits(t *testing.T) {
	p, err := CompilePattern("a", 0)
	if err != nil {
		t.Fatal(err)
	}
	oversized := strings.Repeat("a", maxSubBytes+1)
	tests := map[string]struct{ run func() error }{
		"error: subject exceeds cap":     {run: func() error { _, err := p.SearchString(oversized); return err }},
		"error: replacement exceeds cap": {run: func() error { _, err := p.SubString(oversized, "a", 0); return err }},
		"error: output exceeds cap before writing": {run: func() error {
			var b strings.Builder
			if err := appendBounded(&b, "a"); err != nil {
				return err
			}
			err := appendBounded(&b, oversized[:maxSubBytes])
			if b.String() != "a" {
				t.Fatal("output limit wrote a partial addition")
			}
			return err
		}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := test.run(); err == nil {
				t.Fatal("oversized input accepted")
			}
		})
	}
}

func TestPatternAbandoned(t *testing.T) {
	previous := logger.Load()
	t.Cleanup(func() { logger.Store(previous) })
	logs := 0
	SetLogger(func(string, error) { logs++ })
	p, err := CompilePattern(`(?=a)(a+)+$`, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.bt.MatchTimeout != MatchTimeout || p.nonempty.MatchTimeout != MatchTimeout {
		t.Fatal("fallback timeout is not installed")
	}
	p.bt.MatchTimeout = time.Nanosecond
	subject := strings.Repeat("a", 1000) + "!"
	m, err := p.SearchString(subject)
	if m != nil || err == nil {
		t.Fatalf("search = %v, %v; want an abandoned search", m, err)
	}
	if strings.Contains(err.Error(), subject) {
		t.Fatal("timeout error exposed the whole subject")
	}
	out, err := p.SubString("x", subject, 0)
	if out != "" || err == nil {
		t.Fatalf("substitution = %q, %v; want an abandoned search", out, err)
	}
	if logs != 0 {
		t.Fatalf("error-returning methods logged %d times", logs)
	}
	if p.MatchString(subject) || logs != 1 {
		t.Fatal("Matcher did not log abandonment exactly once")
	}
	matched, abandoned := MatchStringReportTimeout(p, subject, time.Nanosecond)
	if matched || !abandoned || logs != 1 {
		t.Fatal("reporting helper did not preserve its no-logging contract")
	}
}

func TestPatternRetryAbandoned(t *testing.T) {
	p, err := CompilePattern(`|(?=a)(a+)+$`, 0)
	if err != nil {
		t.Fatal(err)
	}
	p.nonempty.MatchTimeout = time.Nanosecond
	out, err := p.SubString("x", strings.Repeat("a", 1000)+"!", 0)
	if out != "" || err == nil {
		t.Fatalf("retry = %q, %v; want no partial output after abandonment", out, err)
	}
}

func TestPatternEngine(t *testing.T) {
	tests := map[string]struct {
		pattern   string
		backtrack bool
	}{
		"success: RE2 preferred":          {pattern: `(a)(b)`},
		"success: empty pattern fallback": {pattern: `x*`, backtrack: true},
		"success: dollar fallback":        {pattern: `a$`, backtrack: true},
		"success: lookaround fallback":    {pattern: `(?=a)a`, backtrack: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := CompilePattern(test.pattern, 0)
			if err != nil {
				t.Fatal(err)
			}
			if p.Pattern() != test.pattern || IsBacktracking(p) != test.backtrack {
				t.Fatal("pattern metadata or engine disagrees")
			}
		})
	}
}

func TestPatternInvalidUTF8(t *testing.T) {
	if _, err := CompilePattern("\xff", Unicode); err == nil {
		t.Fatal("invalid UTF-8 string pattern accepted")
	}
	p, err := CompilePattern(`a`, Unicode)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct{ run func() error }{
		"error: invalid string subject":     {run: func() error { _, err := p.SearchString("\xff"); return err }},
		"error: invalid string replacement": {run: func() error { _, err := p.SubString("\xff", "a", 0); return err }},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := test.run(); err == nil {
				t.Fatal("invalid UTF-8 accepted in string mode")
			}
		})
	}
}
