// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package regex

import (
	"bytes"
	"fmt"
	"log/slog"
	"strconv"
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
		"success: ascii flag in a bytes pattern changes nothing": {
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
		// Python ends a comment at the first ) that no backslash escapes,
		// and a comment binds to nothing: a(?#c)*b is a*b.
		"success: comment with an escaped paren": {
			pattern: `(?#a\)b)c`,
			probes:  []probe{{"c", true}, {"b)", false}},
		},
		"success: comment before a quantifier": {
			pattern: `a(?#c)*b`,
			probes:  []probe{{"b", true}, {"aaab", true}, {"a", false}},
		},
		"success: comment between a back-reference and a digit": {
			pattern:      `(a)\1(?#c)0`,
			backtracking: true,
			probes:       []probe{{"aa0", true}, {"a\b", false}},
		},
		"success: comment inside what looks like a repeat": {
			pattern: `a{1(?#c),2}`,
			probes:  []probe{{"a{1,2}", true}, {"aa", false}},
		},
		"success: comment holding a flag group": {
			pattern: `(?#x(?i)a`,
			probes:  []probe{{"a", true}, {"A", false}},
		},
		// Global flag groups may follow comments, and once one has turned
		// on verbose, whitespace and # comments.
		"success: comment before global flags": {
			pattern:   `(?#c)(?i)a`,
			wantFlags: IgnoreCase,
			probes:    []probe{{"A", true}},
		},
		"success: comment between global flags": {
			pattern:   `(?s)(?#c)(?i)a.`,
			wantFlags: IgnoreCase | DotAll,
			probes:    []probe{{"A\n", true}},
		},
		"success: whitespace after verbose before global flags": {
			pattern:      `(?x) (?i)a`,
			wantFlags:    IgnoreCase,
			backtracking: true,
			probes:       []probe{{"A", true}},
		},
		"success: verbose comment before global flags": {
			pattern:      "(?x)# c\n(?i)a",
			wantFlags:    IgnoreCase,
			backtracking: true,
			probes:       []probe{{"A", true}},
		},
		"success: whitespace between three global groups": {
			pattern:      `(?x)(?i) (?s) a`,
			wantFlags:    IgnoreCase | DotAll,
			backtracking: true,
			probes:       []probe{{"A", true}},
		},
		"success: verbose comment holding a flag group": {
			pattern:      "(?x)a # (?i)\nb",
			backtracking: true,
			probes:       []probe{{"ab", true}, {"aB", false}},
		},
		"success: verbose comment before a quantifier": {
			pattern:      "(?x)a #c\n*b",
			backtracking: true,
			probes:       []probe{{"b", true}, {"aaab", true}},
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
		// Python accepts \N{...} in a str pattern; see docs/compat.md.
		"error: named character": {pattern: `\N{DIGIT ZERO}`},
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

// TestCompileFlagGroupError checks inline flag groups and comments that
// Python 3.13 rejects, with Python's message.
func TestCompileFlagGroupError(t *testing.T) {
	tests := map[string]struct {
		pattern string
		wantErr string
	}{
		"error: global flags after a space without verbose": {pattern: `(?i) (?x)a`, wantErr: "global flags (?x) not at the start"},
		"error: global flags after an escaped space":        {pattern: `(?x)\ (?i)a`, wantErr: "global flags (?i) not at the start"},
		"error: unterminated comment":                       {pattern: `(?#a`, wantErr: "missing ), unterminated comment"},
		"error: flag turned on and off":                     {pattern: `(?i-i:a)`, wantErr: "bad inline flags: flag turned on and off"},
		"error: dash without flags after a":                 {pattern: `(?a-:x)`, wantErr: "missing flag"},
		"error: dash without any flags":                     {pattern: `(?-:x)`, wantErr: "missing flag"},
		"error: dash without flags after i":                 {pattern: `(?i-:x)`, wantErr: "missing flag"},
		"error: two dashes in a row":                        {pattern: `(?i--s:x)`, wantErr: "missing flag"},
		"error: a second dash":                              {pattern: `(?i-s-m:x)`, wantErr: "missing :"},
	}
	for name, tt := range tests {
		for _, mode := range []Flags{0, Unicode} {
			t.Run(fmt.Sprintf("%s/unicode=%v", name, mode != 0), func(t *testing.T) {
				m, err := Compile(tt.pattern, mode)
				if err == nil {
					t.Fatalf("Compile(%q) = %v, want error", tt.pattern, m)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Compile(%q) error = %q, want it to contain %q", tt.pattern, err, tt.wantErr)
				}
			})
		}
	}
}

// TestCompilePythonRejects checks patterns that both Go engines would
// accept but Python 3.13 rejects, with Python's message, for str and bytes
// patterns alike, and the patterns next to them that Python accepts. A
// quantifier after a comment, or after verbose whitespace, cannot make the
// quantifier before it lazy or possessive: Python sees a second repeat.
func TestCompilePythonRejects(t *testing.T) {
	tests := map[string]struct {
		pattern string
		wantErr string
	}{
		"error: ? after a comment after *":         {pattern: `a*(?#c)?`, wantErr: "multiple repeat"},
		"error: ? after a comment after {n}":       {pattern: `a{2}(?#c)?`, wantErr: "multiple repeat"},
		"error: ? after a comment after ?":         {pattern: `a?(?#c)?`, wantErr: "multiple repeat"},
		"error: ? after a comment after a lazy *":  {pattern: `a*?(?#c)?`, wantErr: "multiple repeat"},
		"error: ? after two comments":              {pattern: `a*(?#c)(?#d)?`, wantErr: "multiple repeat"},
		"error: {,} after a comment":               {pattern: `a*(?#c){,}`, wantErr: "multiple repeat"},
		"error: repeat of an escaped backslash":    {pattern: `\\*(?#c)?`, wantErr: "multiple repeat"},
		"error: * after a comment after a comment": {pattern: `a(?#c)*(?#d)?`, wantErr: "multiple repeat"},
		"error: ? after verbose whitespace":        {pattern: `(?x)a* ?`, wantErr: "multiple repeat"},
		"error: ? after a verbose comment":         {pattern: "(?x)a*#c\n?", wantErr: "multiple repeat"},
		"error: ? after a comment and whitespace":  {pattern: `(?x)a* (?#c) ?`, wantErr: "multiple repeat"},
		"error: {n} after verbose whitespace":      {pattern: `(?x)a{2} ?`, wantErr: "multiple repeat"},
		"error: scoped verbose whitespace":         {pattern: `(?x:a* ?)`, wantErr: "multiple repeat"},
		"error: \\x{...}":                          {pattern: `\x{41}`, wantErr: `incomplete escape \x`},
		"error: \\x{...} in a class":               {pattern: `[\x{41}]`, wantErr: `incomplete escape \x`},
		"error: \\x{...} in a class with \\w":      {pattern: `[\w\x{41}]`, wantErr: `incomplete escape \x`},
		"error: \\p{...}":                          {pattern: `\p{L}`, wantErr: `bad escape \p`},
		"error: \\p{...} in a class with \\d":      {pattern: `[\d\p{L}]`, wantErr: `bad escape \p`},
		"error: \\P{...} in a class":               {pattern: `[\P{L}]`, wantErr: `bad escape \P`},
		"error: \\p without braces in a class":     {pattern: `[\pL]`, wantErr: `bad escape \p`},
		"success: comment before a quantifier":     {pattern: `a(?#c)?`},
		"success: lazy quantifiers":                {pattern: `a*?b+?`},
		"success: comments without a quantifier":   {pattern: `a*(?#c)(?#d)`},
		"success: escaped star before a comment":   {pattern: `a\*(?#c)?`},
		"success: group before a comment":          {pattern: `(?:a*)(?#c)?`},
		"success: class before a comment":          {pattern: `[a*](?#c)?`},
		"success: literal brace after a comment":   {pattern: `a*(?#c){x`},
		"success: empty braces after a comment":    {pattern: `a*(?#c){}`},
		"success: open brace after a comment":      {pattern: `a*(?#c){1,`},
		"success: verbose whitespace before {n}":   {pattern: `(?x)a {2}`},
		"success: optional open paren":             {pattern: `\(?a`},
		"success: escaped p and x":                 {pattern: `\\p\\x{41}`},
		"success: \\x with two digits":             {pattern: `[\x41]\x41`},
	}
	for name, tt := range tests {
		for _, mode := range []Flags{0, Unicode} {
			t.Run(fmt.Sprintf("%s/unicode=%v", name, mode != 0), func(t *testing.T) {
				m, err := Compile(tt.pattern, mode)
				if tt.wantErr == "" {
					if err != nil {
						t.Fatalf("Compile(%q) error = %v, Python accepts it", tt.pattern, err)
					}
					return
				}
				if err == nil {
					t.Fatalf("Compile(%q) = %v, want error %q", tt.pattern, m, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Compile(%q) error = %q, want it to contain %q", tt.pattern, err, tt.wantErr)
				}
			})
		}
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

// TestTimeoutReportOmitsSubject checks what an abandoned match reports: the
// time limit, the subject's length and at most its first 64 bytes, quoted,
// never the whole subject, which in a proxy can be a whole message body.
// The log line of the default Logger stays short however long the subject.
func TestTimeoutReportOmitsSubject(t *testing.T) {
	const pattern = "(?=a)(a+)+$"
	tests := map[string]struct {
		subject string
		want    string
	}{
		"success: a 1 MiB subject is cut to 64 bytes": {
			subject: strings.Repeat("a", 1<<20) + "b",
			want:    `match abandoned after 100ms on a 1048577-byte subject starting "` + strings.Repeat("a", 64) + `"`,
		},
		"success: the cut does not split a character": {
			subject: strings.Repeat("a", 63) + "é" + strings.Repeat("a", 64) + "b",
			want:    `match abandoned after 100ms on a 130-byte subject starting "` + strings.Repeat("a", 63) + `"`,
		},
		"success: control characters are escaped": {
			subject: "\x1b[31m\n" + strings.Repeat("a", 64) + "b",
			want:    `match abandoned after 100ms on a 71-byte subject starting "\x1b[31m\n` + strings.Repeat("a", 58) + `"`,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := Compile(pattern, 0)
			if err != nil {
				t.Fatalf("Compile(%q) error = %v", pattern, err)
			}
			var buf bytes.Buffer
			old := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
			t.Cleanup(func() { slog.SetDefault(old) })
			var got []error
			SetLogger(func(p string, err error) {
				got = append(got, err)
				warnTimeout(p, err)
			})
			t.Cleanup(func() { SetLogger(nil) })

			if m.MatchString(tt.subject) {
				t.Fatalf("MatchString() = true, want false after timeout")
			}
			if len(got) != 1 {
				t.Fatalf("logger called %d times, want 1", len(got))
			}
			if diff := gocmp.Diff(tt.want, got[0].Error()); diff != "" {
				t.Errorf("reported error mismatch (-want +got):\n%s", diff)
			}
			line := buf.String()
			if !strings.Contains(line, "level=WARN") || !strings.Contains(line, "pattern="+strconv.Quote(pattern)) {
				t.Errorf("log line %q lacks the level or the pattern", line)
			}
			if len(line) > 512 {
				t.Errorf("log line is %d bytes, want at most 512: %.200q", len(line), line)
			}
		})
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

// fuzzCompileBound is how long FuzzCompile lets one Compile take. A
// translation that scans a pattern more than once per character, or emits
// a pattern that grows faster than its input, shows up as a compile far
// above it.
const fuzzCompileBound = time.Second

// FuzzCompile compiles arbitrary patterns as str and bytes patterns, with
// and without IgnoreCase. A pattern may be rejected, but Compile must not
// panic or take longer than fuzzCompileBound, and a compiled Matcher must
// run on a short subject that holds the characters the translation treats
// specially.
func FuzzCompile(f *testing.F) {
	seeds := []string{
		`\b[\w_]+Z`, `[\w_]+(?=Z)`, `[\da-f0-9]+`, `[^\W_]`, `[\s\S]`, `[]\w]`, `[!--\w]`,
		`[[:alpha:]]`, `x[[:digit:]\d]`, `[\w.-[]`, `[^[\d]`,
		`(?ias:x)`, `(?sai:x)`, `(?a)(?u:\d)`, `(?L:\w)`, `(?ai-s:\w)`,
		`(?#a\)b)c`, `a(?#c)*b`, `(a)\1(?#c)0`, "(?x) (?i)a", "(?x)a # (?i)\nb", `(?i-i:a)`, `(?a-:x)`, `\N{DIGIT ZERO}`,
		"(?i)x(?=)|(?-i:[\u212a-\u212b])", `a*(?#c)?`, `(?x)a* ?`, `[\w\x{41}]`, `[\d\p{L}]`, `\.js$`, `(a$)+`, `a\Z`, `\B`, `(?=a)(a+)+$`,
		strings.Repeat("(?=a)", 64), strings.Repeat(`\B`, 32),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	SetLogger(nil)
	f.Cleanup(func() { SetLogger(nil) })
	const subject = "aK_ 1\n\u0663\u00e9\u212a[]-"
	f.Fuzz(func(t *testing.T, pattern string) {
		for _, flags := range []Flags{0, IgnoreCase, Unicode, Unicode | IgnoreCase} {
			start := time.Now()
			m, err := Compile(pattern, flags)
			if elapsed := time.Since(start); elapsed > fuzzCompileBound {
				t.Fatalf("Compile(%q, %d) took %v, more than %v", pattern, flags, elapsed, fuzzCompileBound)
			}
			if err != nil {
				continue
			}
			if got := m.Pattern(); got != pattern {
				t.Fatalf("Compile(%q, %d).Pattern() = %q", pattern, flags, got)
			}
			m.MatchString(subject)
		}
	})
}
