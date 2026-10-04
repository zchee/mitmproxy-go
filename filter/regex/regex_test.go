// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package regex

import (
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestFlagsString(t *testing.T) {
	tests := map[string]struct {
		flags Flags
		want  string
	}{
		"success: none":       {flags: 0, want: ""},
		"success: i":          {flags: IgnoreCase, want: "i"},
		"success: im":         {flags: IgnoreCase | Multiline, want: "im"},
		"success: is":         {flags: DotAll | IgnoreCase, want: "is"},
		"success: all in ims": {flags: DotAll | Multiline | IgnoreCase, want: "ims"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tt.flags.String(); got != tt.want {
				t.Errorf("Flags(%d).String() = %q, want %q", tt.flags, got, tt.want)
			}
		})
	}
}

func TestCompile(t *testing.T) {
	type probe struct {
		input string
		want  bool
	}
	tests := map[string]struct {
		pattern      string
		flags        Flags
		backtracking bool
		wantFlags    Flags
		probes       []probe
	}{
		"success: plain literal searches anywhere": {
			pattern: "foo",
			probes:  []probe{{"xfoox", true}, {"FOO", false}, {"fo", false}},
		},
		"success: ignore case": {
			pattern:   "foo",
			flags:     IgnoreCase,
			wantFlags: IgnoreCase,
			probes:    []probe{{"xFoOx", true}, {"bar", false}},
		},
		"success: multiline anchors at line starts": {
			pattern:   "^host: example",
			flags:     Multiline,
			wantFlags: Multiline,
			probes:    []probe{{"accept: */*\r\nhost: example.com\r\n", true}, {"xhost: example", false}},
		},
		"success: without multiline ^ anchors at input start only": {
			pattern: "^host",
			probes:  []probe{{"a\nhost", false}, {"host", true}},
		},
		"success: dotall lets dot cross newlines": {
			pattern:   "a.b",
			flags:     DotAll,
			wantFlags: DotAll,
			probes:    []probe{{"a\nb", true}},
		},
		"success: without dotall dot stops at newlines": {
			pattern: "a.b",
			probes:  []probe{{"a\nb", false}, {"axb", true}},
		},
		"success: leading inline flags are reported": {
			pattern:   "(?s)a.b",
			flags:     IgnoreCase,
			wantFlags: IgnoreCase | DotAll,
			probes:    []probe{{"A\nB", true}},
		},
		"success: several leading inline flag groups": {
			pattern:   "(?i)(?m)^b",
			wantFlags: IgnoreCase | Multiline,
			probes:    []probe{{"a\nB", true}},
		},
		"success: python-only inline flags are dropped": {
			pattern:   "(?a)\\w+",
			wantFlags: 0,
			probes:    []probe{{"abc", true}},
		},
		"success: scoped inline flags are not global": {
			pattern:   "(?s:a.b)",
			wantFlags: 0,
			probes:    []probe{{"a\nb", true}},
		},
		"success: verbose flag compiles through regexp2": {
			pattern:      "(?x) a b # comment",
			backtracking: true,
			probes:       []probe{{"ab", true}, {"a b", false}},
		},
		"success: python \\Z is the absolute end": {
			pattern: `foo\Z`,
			probes:  []probe{{"foo", true}, {"foo\n", false}, {"foox", false}},
		},
		"success: escaped backslash before Z is left alone": {
			pattern: `a\\Z`,
			probes:  []probe{{`a\Z`, true}, {"a", false}},
		},
		"success: lookahead falls back to regexp2": {
			pattern:      "foo(?=bar)",
			backtracking: true,
			probes:       []probe{{"foobar", true}, {"foobaz", false}},
		},
		"success: negative lookbehind falls back to regexp2": {
			pattern:      "(?<!x)foo",
			backtracking: true,
			probes:       []probe{{"yfoo", true}, {"xfoo", false}, {"foo", true}},
		},
		"success: backreference falls back to regexp2": {
			pattern:      `(\w)\1`,
			backtracking: true,
			probes:       []probe{{"abba", true}, {"abc", false}},
		},
		"success: regexp2 honours ignore case and dotall": {
			pattern:      "a(?=.B)",
			flags:        IgnoreCase | DotAll,
			wantFlags:    IgnoreCase | DotAll,
			backtracking: true,
			probes:       []probe{{"A\nb", true}, {"A\nc", false}},
		},
		"success: regexp2 honours multiline": {
			pattern:      "^b(?=c)",
			flags:        Multiline,
			wantFlags:    Multiline,
			backtracking: true,
			probes:       []probe{{"a\nbc", true}, {"a\nbd", false}},
		},
		"success: flag-like text inside a class": {
			pattern: "[(?i)]",
			probes:  []probe{{"?", true}, {"I", false}},
		},
		"success: scoped flags mid-pattern": {
			pattern: "a(?i:b)",
			probes:  []probe{{"aB", true}, {"AB", false}},
		},
		"success: named group": {
			pattern: "(?P<n>a)b",
			probes:  []probe{{"ab", true}},
		},
		"success: tail dollar matches before a final newline": {
			pattern: "foo$",
			probes:  []probe{{"foo", true}, {"foo\n", true}, {"foo\n\n", false}, {"foo\nx", false}, {"foox", false}},
		},
		"success: tail dollar in every alternative": {
			pattern: "(?:a$|b$)",
			probes:  []probe{{"xa\n", true}, {"xb", true}, {"ab\nc", false}},
		},
		"success: tail dollar inside a capture": {
			pattern: `\.(js|css)$`,
			probes:  []probe{{"/app.js\n", true}, {"/app.css", true}, {"/app.js?x", false}},
		},
		"success: tail dollar with dotall": {
			pattern:   "a.$",
			flags:     DotAll,
			wantFlags: DotAll,
			probes:    []probe{{"a\n", true}, {"ab\n", true}, {"ab\nc", false}},
		},
		"success: multiline dollar is left to RE2": {
			pattern:   "^a$",
			flags:     Multiline,
			wantFlags: Multiline,
			probes:    []probe{{"x\na\ny", true}, {"x\nab", false}},
		},
		"success: scoped multiline dollar is left to RE2": {
			pattern: "(?m:a$)b",
			probes:  []probe{{"ab", false}, {"a\nb", false}},
		},
		"success: escaped dollar is a literal": {
			pattern: `a\$`,
			probes:  []probe{{"a$", true}, {"a\n", false}},
		},
		"success: dollar inside a class is a literal": {
			pattern: "a[$]",
			probes:  []probe{{"a$", true}, {"a", false}},
		},
		"success: dollar before more pattern uses regexp2": {
			pattern:      "a$\n",
			backtracking: true,
			probes:       []probe{{"a\n", true}, {"a", false}, {"a\n\n", false}},
		},
		"success: dollar under repetition uses regexp2": {
			pattern:      "(?:a$)+",
			backtracking: true,
			probes:       []probe{{"xa\n", true}, {"xa", true}, {"xab", false}},
		},
		"success: dollar under ignore case": {
			pattern:   "FOO$",
			flags:     IgnoreCase,
			wantFlags: IgnoreCase,
			probes:    []probe{{"x foo\n", true}, {"foo bar", false}},
		},
		"success: python \\Z does not match before a final newline": {
			pattern: `a\Z|b$`,
			probes:  []probe{{"a\n", false}, {"b\n", true}, {"a", true}},
		},
		"success: empty pattern matches everything": {
			pattern: "",
			probes:  []probe{{"", true}, {"anything", true}},
		},
		"success: non-ascii pattern": {
			pattern:   "шгн",
			flags:     IgnoreCase,
			wantFlags: IgnoreCase,
			probes:    []probe{{"xШГНx", true}, {"abc", false}},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := Compile(tt.pattern, tt.flags)
			if err != nil {
				t.Fatalf("Compile(%q, %v) error = %v", tt.pattern, tt.flags, err)
			}
			if got := IsBacktracking(m); got != tt.backtracking {
				t.Errorf("IsBacktracking() = %v, want %v", got, tt.backtracking)
			}
			if got := m.Flags(); got != tt.wantFlags {
				t.Errorf("Flags() = %q, want %q", got, tt.wantFlags)
			}
			if got := m.Pattern(); got != tt.pattern {
				t.Errorf("Pattern() = %q, want %q", got, tt.pattern)
			}
			for _, p := range tt.probes {
				if got := m.MatchString(p.input); got != p.want {
					t.Errorf("MatchString(%q) = %v, want %v", p.input, got, p.want)
				}
				if got := m.Match([]byte(p.input)); got != p.want {
					t.Errorf("Match(%q) = %v, want %v", p.input, got, p.want)
				}
			}
		})
	}
}

func TestCompileError(t *testing.T) {
	tests := map[string]struct {
		pattern string
	}{
		"error: unterminated class":       {pattern: "["},
		"error: unbalanced paren":         {pattern: "(a"},
		"error: stray close paren":        {pattern: "a)"},
		"error: nothing to repeat":        {pattern: "*a"},
		"error: unterminated lookahead":   {pattern: "(?=a"},
		"error: global flags mid-pattern": {pattern: "a(?i)"},
		"error: negated global flags":     {pattern: "(?-i)a"},
		"error: ungreedy flag":            {pattern: "(?U)a+"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := Compile(tt.pattern, IgnoreCase)
			if err == nil {
				t.Fatalf("Compile(%q) = %v, want error", tt.pattern, m)
			}
			if !strings.Contains(err.Error(), tt.pattern) {
				t.Errorf("error %q does not name the pattern %q", err, tt.pattern)
			}
		})
	}
}

// TestCatastrophicBacktrackingTimesOut feeds a pattern that needs regexp2
// (it has a lookahead) and backtracks exponentially on a near-miss input.
func TestCatastrophicBacktrackingTimesOut(t *testing.T) {
	var (
		mu     sync.Mutex
		logged []string
	)
	SetLogger(func(pattern string, err error) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, pattern)
		if err == nil {
			t.Errorf("logger called with nil error for %q", pattern)
		}
	})
	t.Cleanup(func() { SetLogger(nil) })

	const pattern = "(?=a)(a+)+$"
	m, err := Compile(pattern, 0)
	if err != nil {
		t.Fatalf("Compile(%q) error = %v", pattern, err)
	}
	if !IsBacktracking(m) {
		t.Fatalf("Compile(%q) did not fall back to regexp2", pattern)
	}

	input := strings.Repeat("a", 64) + "b"
	start := time.Now()
	got := m.MatchString(input)
	elapsed := time.Since(start)
	if got {
		t.Errorf("MatchString(%q) = true, want false after timeout", input)
	}
	if elapsed < MatchTimeout {
		t.Errorf("match returned after %v, before the %v timeout; the timeout path was not exercised", elapsed, MatchTimeout)
	}
	if elapsed > 20*MatchTimeout {
		t.Errorf("match took %v, far beyond the %v timeout", elapsed, MatchTimeout)
	}
	mu.Lock()
	defer mu.Unlock()
	if diff := gocmp.Diff([]string{pattern}, logged); diff != "" {
		t.Errorf("logged patterns mismatch (-want +got):\n%s", diff)
	}
}

func TestSetLoggerNilDiscards(t *testing.T) {
	SetLogger(nil)
	t.Cleanup(func() { SetLogger(nil) })
	m, err := Compile("(?=a)(a+)+$", 0)
	if err != nil {
		t.Fatal(err)
	}
	if m.MatchString(strings.Repeat("a", 64) + "b") {
		t.Error("MatchString() = true, want false after timeout")
	}
}

func BenchmarkMatch(b *testing.B) {
	headers := []byte(strings.Repeat("x-padding: 0123456789abcdef\r\n", 20) + "content-type: application/json\r\n")
	benchmarks := map[string]struct {
		pattern string
		flags   Flags
	}{
		"re2":     {pattern: "^content-type: application/json"},
		"regexp2": {pattern: "^content-type: (?=application)"},
		// Class escapes: on RE2 in both modes, on regexp2, and \b in a str
		// pattern, which runs on regexp2.
		"re2 bytes class":   {pattern: `^content-type: \w+/json`},
		"re2 str class":     {pattern: `^content-type: \w+/json`, flags: Unicode},
		"regexp2 class":     {pattern: `^content-type: \w+(?=/json)`, flags: Unicode},
		"str word boundary": {pattern: `\bjson\b`, flags: Unicode},
	}
	for name, bm := range benchmarks {
		b.Run(name, func(b *testing.B) {
			m, err := Compile(bm.pattern, bm.flags|IgnoreCase|Multiline)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(headers)))
			for b.Loop() {
				if !m.Match(headers) {
					b.Fatal("no match")
				}
			}
		})
	}
}
