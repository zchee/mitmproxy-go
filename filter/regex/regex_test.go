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
		// Python: "nothing to repeat".
		"error: {,} after an open group": {pattern: `(?:{,})`},
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
		"error: ? after a comment after *":               {pattern: `a*(?#c)?`, wantErr: "multiple repeat"},
		"error: ? after a comment after {n}":             {pattern: `a{2}(?#c)?`, wantErr: "multiple repeat"},
		"error: ? after a comment after ?":               {pattern: `a?(?#c)?`, wantErr: "multiple repeat"},
		"error: ? after a comment after a lazy *":        {pattern: `a*?(?#c)?`, wantErr: "multiple repeat"},
		"error: ? after two comments":                    {pattern: `a*(?#c)(?#d)?`, wantErr: "multiple repeat"},
		"error: {,} after a comment":                     {pattern: `a*(?#c){,}`, wantErr: "multiple repeat"},
		"error: repeat of an escaped backslash":          {pattern: `\\*(?#c)?`, wantErr: "multiple repeat"},
		"error: * after a comment after a comment":       {pattern: `a(?#c)*(?#d)?`, wantErr: "multiple repeat"},
		"error: ? after verbose whitespace":              {pattern: `(?x)a* ?`, wantErr: "multiple repeat"},
		"error: ? after a verbose comment":               {pattern: "(?x)a*#c\n?", wantErr: "multiple repeat"},
		"error: ? after a comment and whitespace":        {pattern: `(?x)a* (?#c) ?`, wantErr: "multiple repeat"},
		"error: {n} after verbose whitespace":            {pattern: `(?x)a{2} ?`, wantErr: "multiple repeat"},
		"error: scoped verbose whitespace":               {pattern: `(?x:a* ?)`, wantErr: "multiple repeat"},
		"error: \\x{...}":                                {pattern: `\x{41}`, wantErr: `incomplete escape \x`},
		"error: \\x{...} in a class":                     {pattern: `[\x{41}]`, wantErr: `incomplete escape \x`},
		"error: \\x{...} in a class with \\w":            {pattern: `[\w\x{41}]`, wantErr: `incomplete escape \x`},
		"error: \\p{...}":                                {pattern: `\p{L}`, wantErr: `bad escape \p`},
		"error: \\p{...} in a class with \\d":            {pattern: `[\d\p{L}]`, wantErr: `bad escape \p`},
		"error: \\P{...} in a class":                     {pattern: `[\P{L}]`, wantErr: `bad escape \P`},
		"error: unknown group before its definition":     {pattern: `(?P=n)(?P<n>a)`, wantErr: "unknown group name 'n'"},
		"error: unknown group name":                      {pattern: `(?P<n>a)(?P=m)`, wantErr: "unknown group name 'm'"},
		"error: unterminated backreference name":         {pattern: `(?P<n>a)(?P=n`, wantErr: "missing ), unterminated name"},
		"error: unterminated group name":                 {pattern: `(?P<n`, wantErr: "missing >, unterminated name"},
		"error: empty backreference name":                {pattern: `(?P<n>a)(?P=)`, wantErr: "missing group name"},
		"error: empty group name":                        {pattern: `(?P<>a)`, wantErr: "missing group name"},
		"error: digit as a backreference name":           {pattern: `(?P<n>a)(?P=1)`, wantErr: "bad character in group name '1'"},
		"error: name starting with a digit":              {pattern: `(?P<1n>a)`, wantErr: "bad character in group name '1n'"},
		"error: unknown name in a conditional":           {pattern: `(?P<n>a)?(?(m)b|c)`, wantErr: "unknown group name 'm'"},
		"error: conditional on a missing group":          {pattern: `(a)?(?(2)b|c)`, wantErr: "invalid group reference 2"},
		"error: conditional on group 1 of none":          {pattern: `(?(1)a)`, wantErr: "invalid group reference 1"},
		"error: conditional on group 0":                  {pattern: `(a)(?(0)b)`, wantErr: "bad group number"},
		"error: lookahead as a condition":                {pattern: `(?(?=a)a|b)`, wantErr: "bad character in group name '?=a'"},
		"error: redefined group name":                    {pattern: `(?P<n>a)(?P<n>b)`, wantErr: "redefinition of group name 'n' as group 2; was group 1"},
		"error: named backreference to an open group":    {pattern: `(?P<n>(?P=n)a)`, wantErr: "cannot refer to an open group"},
		"error: numbered backreference to an open group": {pattern: `((.)\1+)`, wantErr: "cannot refer to an open group"},
		"error: backreference to a missing group":        {pattern: `((((((((((a))))))))))\41`, wantErr: "invalid group reference 41"},
		"error: forward backreference":                   {pattern: `\2(a)(b)`, wantErr: "invalid group reference 2"},
		"error: octal escape out of range":               {pattern: `\477`, wantErr: "octal escape value \\477 outside of range 0-0o377"},
		"error: unknown extension ?P":                    {pattern: `(?Px)`, wantErr: "unknown extension ?Px"},
		"error: named group without P":                   {pattern: `(?<n>a)`, wantErr: "unknown extension ?<n"},
		"error: quoted group name":                       {pattern: `(?'n'a)`, wantErr: "unknown extension ?'"},
		"error: backreference spelled \\k":               {pattern: `(?P<n>a)\k<n>`, wantErr: "bad escape \\k"},
		"error: star after ^":                            {pattern: `^*`, wantErr: "nothing to repeat"},
		"error: plus after ^":                            {pattern: `^+a`, wantErr: "nothing to repeat"},
		"error: braces after ^":                          {pattern: `^{2}a`, wantErr: "nothing to repeat"},
		"error: ? after $":                               {pattern: `a$?`, wantErr: "nothing to repeat"},
		"error: star after \\A":                          {pattern: `\A*a`, wantErr: "nothing to repeat"},
		"error: ? after \\Z":                             {pattern: `a\Z?`, wantErr: "nothing to repeat"},
		"error: star after \\b":                          {pattern: `\b*a`, wantErr: "nothing to repeat"},
		"error: plus after \\B":                          {pattern: `\B+a`, wantErr: "nothing to repeat"},
		"error: star after ^ in an alternative":          {pattern: `a|^*`, wantErr: "nothing to repeat"},
		"error: star after a multiline ^":                {pattern: `(?m)^*a`, wantErr: "nothing to repeat"},
		"success: group around ^":                        {pattern: `(^)*a`},
		"success: non-capturing group around ^":          {pattern: `(?:^)*a`},
		"success: escaped caret":                         {pattern: `\^*a`},
		"success: negated class":                         {pattern: `[^a]*b`},
		"success: repeated lookahead":                    {pattern: `(?=a)*a`},
		"success: repeated lookbehind":                   {pattern: `(?<=a)*b`},
		"success: literal braces after ^":                {pattern: `^{x}`},
		"error: control escape":                          {pattern: `\cA`, wantErr: "bad escape \\c"},
		"error: escape character":                        {pattern: `\eA`, wantErr: "bad escape \\e"},
		"error: escape character in a class":             {pattern: `[\e]`, wantErr: "bad escape \\e"},
		"error: previous match end":                      {pattern: `\GA`, wantErr: "bad escape \\G"},
		"error: quoted text":                             {pattern: `\QA`, wantErr: "bad escape \\Q"},
		// Python 3.13 rejects \z; 3.14 reads it as \Z. See docs/compat.md.
		"success: end of input spelled \\z":       {pattern: `a\z`},
		"error: minimum above maximum":            {pattern: `a{2,1}`, wantErr: "min repeat greater than max repeat"},
		"error: suffix after a lazy suffix":       {pattern: `a*?+`, wantErr: "multiple repeat"},
		"error: suffix after a possessive suffix": {pattern: `a*++`, wantErr: "multiple repeat"},
		"error: lazy after possessive":            {pattern: `a*+?`, wantErr: "multiple repeat"},
		"error: possessive after lazy +":          {pattern: `a+?+`, wantErr: "multiple repeat"},
		"error: possessive after lazy {n}":        {pattern: `a{2}?+`, wantErr: "multiple repeat"},
		"error: braces after a star":              {pattern: `a*{2}`, wantErr: "multiple repeat"},
		"error: possessive at the start":          {pattern: `*+`, wantErr: "nothing to repeat"},
		"error: possessive opening a group":       {pattern: `(*+)`, wantErr: "nothing to repeat"},
		"error: possessive after a bar":           {pattern: `a|*+`, wantErr: "nothing to repeat"},
		"error: possessive after \\b":             {pattern: `\b*+`, wantErr: "nothing to repeat"},
		"error: possessive after ^":               {pattern: `^*+`, wantErr: "nothing to repeat"},
		"error: \\p without braces in a class":    {pattern: `[\pL]`, wantErr: `bad escape \p`},
		"success: comment before a quantifier":    {pattern: `a(?#c)?`},
		"success: lazy quantifiers":               {pattern: `a*?b+?`},
		"success: comments without a quantifier":  {pattern: `a*(?#c)(?#d)`},
		"success: escaped star before a comment":  {pattern: `a\*(?#c)?`},
		"success: group before a comment":         {pattern: `(?:a*)(?#c)?`},
		"success: class before a comment":         {pattern: `[a*](?#c)?`},
		"success: literal brace after a comment":  {pattern: `a*(?#c){x`},
		"success: empty braces after a comment":   {pattern: `a*(?#c){}`},
		"success: open brace after a comment":     {pattern: `a*(?#c){1,`},
		"success: verbose whitespace before {n}":  {pattern: `(?x)a {2}`},
		"success: optional open paren":            {pattern: `\(?a`},
		"success: escaped p and x":                {pattern: `\\p\\x{41}`},
		"success: \\x with two digits":            {pattern: `[\x41]\x41`},
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

// TestCompileBraceRepeat checks the {m,n} forms against Python 3.13's
// re.search: a missing minimum is 0 and a missing maximum is unbounded, so
// {,} and {,n} repeat, while any { that does not start digits, an optional
// comma and digits closed by } is literal text, also in verbose mode. Each
// pattern runs as written and, behind a (?=) that only regexp2 can run, on
// regexp2, in str and bytes mode.
func TestCompileBraceRepeat(t *testing.T) {
	type probe struct {
		input string
		want  bool
	}
	tests := map[string]struct {
		pattern string
		probes  []probe
	}{
		"success: {,} repeats from 0 up":       {pattern: `^a{,}$`, probes: []probe{{"", true}, {"a", true}, {"aaaa", true}, {"a{,}", false}}},
		"success: {,n} repeats from 0 to n":    {pattern: `^a{,2}$`, probes: []probe{{"", true}, {"aa", true}, {"aaa", false}, {"a{,2}", false}}},
		"success: {n,} repeats from n up":      {pattern: `^a{2,}$`, probes: []probe{{"a", false}, {"aa", true}, {"aaaaa", true}}},
		"success: leading zeros":               {pattern: `^a{00,01}$`, probes: []probe{{"", true}, {"a", true}, {"aa", false}}},
		"success: lazy {,}":                    {pattern: `^a{,}?b`, probes: []probe{{"b", true}, {"aab", true}}},
		"success: lazy {,n}":                   {pattern: `^a{,2}?$`, probes: []probe{{"aa", true}, {"aaa", false}}},
		"success: {,n} at RE2's limit":         {pattern: `^x{,1000}$`, probes: []probe{{"", true}, {"xxx", true}}},
		"success: {,n} past RE2's limit":       {pattern: `^x{,1001}$`, probes: []probe{{"", true}, {"xxx", true}}},
		"success: space before the comma":      {pattern: `^a{ ,}$`, probes: []probe{{"a{ ,}", true}, {"a", false}}},
		"success: letter in braces":            {pattern: `^a{a}$`, probes: []probe{{"a{a}", true}, {"a", false}}},
		"success: unterminated brace":          {pattern: `^a{$`, probes: []probe{{"a{", true}, {"a", false}}},
		"success: unterminated count":          {pattern: `^a{,2$`, probes: []probe{{"a{,2", true}, {"aa", false}}},
		"success: empty braces":                {pattern: `^a{}$`, probes: []probe{{"a{}", true}, {"a", false}}},
		"success: space before the count":      {pattern: `^a{ 2}$`, probes: []probe{{"a{ 2}", true}, {"aa", false}}},
		"success: verbose space in the braces": {pattern: `(?x)^a{ 2}$`, probes: []probe{{"a{2}", true}, {"aa", false}, {"a{ 2}", false}}},
		"success: verbose space after {,n":     {pattern: `(?x)^a{,2 }$`, probes: []probe{{"a{,2}", true}, {"aa", false}, {"", false}}},
		"success: verbose {,n}":                {pattern: `(?x)^a{,2}$`, probes: []probe{{"", true}, {"aa", true}, {"a{,2}", false}}},
		"success: braces in a class":           {pattern: `[a{,}]`, probes: []probe{{"{", true}, {",", true}, {"b", false}}},
		"success: escaped brace":               {pattern: `^a\{,}$`, probes: []probe{{"a{,}", true}, {"a", false}}},
	}
	for name, tt := range tests {
		variants := map[string]string{"as written": tt.pattern}
		if !strings.HasPrefix(tt.pattern, "(?x)") {
			variants["regexp2"] = "(?=)" + tt.pattern
		}
		for variant, pattern := range variants {
			for _, mode := range []Flags{0, Unicode} {
				t.Run(fmt.Sprintf("%s/%s/unicode=%v", name, variant, mode != 0), func(t *testing.T) {
					m, err := Compile(pattern, mode)
					if err != nil {
						t.Fatalf("Compile(%q) error = %v", pattern, err)
					}
					if variant == "regexp2" && !IsBacktracking(m) {
						t.Fatalf("Compile(%q) runs on RE2", pattern)
					}
					for _, p := range tt.probes {
						if got := m.MatchString(p.input); got != p.want {
							t.Errorf("Compile(%q).MatchString(%q) = %v, want %v", pattern, p.input, got, p.want)
						}
					}
				})
			}
		}
	}
}

// TestCompilePossessive checks Python 3.11's possessive quantifiers and
// atomic groups against Python 3.13's re.search. A possessive repeat keeps
// everything it matched, so a*+a never matches where a*a does; it runs on
// regexp2 as the atomic group (?>a*), which CPython defines it to be.
// strOnly rows hold a non-ASCII character, which a bytes pattern reads as
// two Latin-1 characters.
func TestCompilePossessive(t *testing.T) {
	type probe struct {
		input string
		want  bool
	}
	tests := map[string]struct {
		pattern string
		probes  []probe
		strOnly bool
		// re2 marks a row without a possessive repeat, which stays on RE2.
		re2 bool
	}{
		"success: *+ keeps the whole run":    {pattern: `a*+a`, probes: []probe{{"aaa", false}, {"b", false}}},
		"success: *+ before the end":         {pattern: `^a*+$`, probes: []probe{{"aaa", true}, {"", true}}},
		"success: *+ before $":               {pattern: `a*+$`, probes: []probe{{"aa", true}}},
		"success: ++":                        {pattern: `a++a`, probes: []probe{{"aaa", false}}},
		"success: ?+":                        {pattern: `a?+a`, probes: []probe{{"a", false}, {"aa", true}}},
		"success: {m,n}+":                    {pattern: `a{1,3}+a`, probes: []probe{{"aaa", false}, {"aaaa", true}}},
		"success: {,}+":                      {pattern: `a{,}+a`, probes: []probe{{"aa", false}}},
		"success: {,n}+":                     {pattern: `a{,2}+a`, probes: []probe{{"aa", false}, {"aaa", true}}},
		"success: {n}+":                      {pattern: `a{2}+`, probes: []probe{{"aa", true}, {"a", false}}},
		"success: class":                     {pattern: `[ab]++b`, probes: []probe{{"aab", false}, {"aabc", false}}},
		"success: one-character class":       {pattern: `[a]*+a`, probes: []probe{{"aa", false}}},
		"success: group with alternatives":   {pattern: `(?:ab|a)++b`, probes: []probe{{"abab", false}, {"aab", false}}},
		"success: capturing group":           {pattern: `(a|ab)++c`, probes: []probe{{"abc", false}, {"ac", true}}},
		"success: single-member group":       {pattern: `(?:a)*+a`, probes: []probe{{"aa", false}}},
		"success: scoped flag group":         {pattern: `(?s:.)*+x`, probes: []probe{{"ax", false}}},
		"success: nested":                    {pattern: `(a*+)*+b`, probes: []probe{{"aab", true}}},
		"success: lookahead":                 {pattern: `(?=a)*+a`, probes: []probe{{"a", true}}},
		"success: class escape":              {pattern: `\d*+1`, probes: []probe{{"111", false}}},
		"success: word class escape":         {pattern: `\w++!`, probes: []probe{{"ab!", true}}},
		"success: hex escape":                {pattern: `\x41*+A`, probes: []probe{{"AA", false}}},
		"success: escaped paren":             {pattern: `\(*+\(`, probes: []probe{{"((", false}}},
		"success: dot":                       {pattern: `.*+x`, probes: []probe{{"abx", false}}},
		"success: comment before quantifier": {pattern: `a(?#c)*+a`, probes: []probe{{"aaa", false}}},
		"success: verbose":                   {pattern: `(?x)a *+ a`, probes: []probe{{"aaa", false}}},
		"success: ignore case":               {pattern: `(?i)A*+a`, probes: []probe{{"aaa", false}}},
		"success: escaped plus is greedy":    {pattern: `a\++`, probes: []probe{{"a++", true}}, re2: true},
		"success: literal brace then +":      {pattern: `a{x}+`, probes: []probe{{"a{x}}}", true}, {"a{x", false}}, re2: true},
		"success: atomic group":              {pattern: `(?>a*)a`, probes: []probe{{"aaa", false}}},
		"success: atomic group then b":       {pattern: `(?>a*)b`, probes: []probe{{"aab", true}}},
		"success: atomic alternation":        {pattern: `(?>a|ab)c`, probes: []probe{{"abc", false}, {"ac", true}}},
		"success: empty atomic group":        {pattern: `(?>)`, probes: []probe{{"a", true}}},
		"success: non-ASCII character":       {pattern: "\u00e9*+\u00e9", probes: []probe{{"\u00e9\u00e9", false}}, strOnly: true},
		"success: \\u escape":                {pattern: `\u00e9*+\u00e9`, probes: []probe{{"\u00e9\u00e9", false}}, strOnly: true},
	}
	for name, tt := range tests {
		modes := []Flags{0, Unicode}
		if tt.strOnly {
			modes = []Flags{Unicode}
		}
		for _, mode := range modes {
			t.Run(fmt.Sprintf("%s/unicode=%v", name, mode != 0), func(t *testing.T) {
				m, err := Compile(tt.pattern, mode)
				if err != nil {
					t.Fatalf("Compile(%q) error = %v", tt.pattern, err)
				}
				if got := IsBacktracking(m); got == tt.re2 {
					t.Errorf("IsBacktracking(Compile(%q)) = %v, want %v", tt.pattern, got, !tt.re2)
				}
				for _, p := range tt.probes {
					if got := m.MatchString(p.input); got != p.want {
						t.Errorf("Compile(%q).MatchString(%q) = %v, want %v", tt.pattern, p.input, got, p.want)
					}
				}
			})
		}
	}
}

// TestCompileGroupReferences checks Python's named groups, named and
// numbered backreferences and conditionals against Python 3.13's
// re.search. regexp2 spells a named group (?<name>...) and a named
// backreference \k<name>, and reads \10 as an octal escape where Python
// reads group 10. strOnly rows hold a non-ASCII name, which a bytes pattern
// rejects.
func TestCompileGroupReferences(t *testing.T) {
	type probe struct {
		input string
		want  bool
	}
	tests := map[string]struct {
		pattern string
		probes  []probe
		strOnly bool
	}{
		"success: named backreference":               {pattern: `(?P<n>a)(?P=n)`, probes: []probe{{"aa", true}, {"ab", false}}},
		"success: named backreference after text":    {pattern: `(?P<n>a)x(?P=n)`, probes: []probe{{"axa", true}, {"axb", false}}},
		"success: repeated named backreference":      {pattern: `(?P<n>a)(?P=n)+`, probes: []probe{{"aaa", true}}},
		"success: backreference in a flag group":     {pattern: `(?P<n>a|b)(?i:(?P=n))`, probes: []probe{{"aA", true}, {"ab", false}}},
		"success: name with digits":                  {pattern: `(?P<n1>a)(?P=n1)`, probes: []probe{{"aa", true}}},
		"success: number of a named group":           {pattern: `(?P<n>a)\1`, probes: []probe{{"aa", true}}},
		"success: numbered and named":                {pattern: `(a)(?P<b>b)\2(?P=b)`, probes: []probe{{"abbb", true}}},
		"success: named conditional":                 {pattern: `(?P<n>a)?(?(n)b|c)`, probes: []probe{{"ab", true}, {"c", true}, {"x", false}}},
		"success: named conditional without no":      {pattern: `(?P<n>a)?(?(n)b)`, probes: []probe{{"ab", true}, {"x", true}}},
		"success: repeated conditional":              {pattern: `(?P<n>a)(?(n)x|y)+`, probes: []probe{{"axx", true}}},
		"success: conditional before \\Z":            {pattern: `(?P<n>x)?(?(n)a|b)\Z`, probes: []probe{{"b", true}, {"xa", true}, {"xc", false}}},
		"success: numbered conditional":              {pattern: `(a)?(?(1)b|c)`, probes: []probe{{"ab", true}, {"c", true}}},
		"success: conditional without no, then text": {pattern: `(a)?(?(1)b)c`, probes: []probe{{"c", true}, {"ab", false}, {"abc", true}}},
		"success: two-digit backreference":           {pattern: `((((((((((a))))))))))\10`, probes: []probe{{"aa", true}, {"a", false}}},
		"success: two digits, then a digit":          {pattern: `(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)(l)\119`, probes: []probe{{"abcdefghijklk9", true}, {"abcdefghijkla9", false}}},
		"success: three octal digits":                {pattern: `(a)\101`, probes: []probe{{"aA", true}, {"aa", false}}},
		"success: backreference, comment, digit":     {pattern: `(a)\1(?#c)0`, probes: []probe{{"aa0", true}, {"a\x010", false}}},
		"success: non-ASCII name":                    {pattern: "(?P<é>a)(?P=é)", probes: []probe{{"aa", true}}, strOnly: true},
	}
	for name, tt := range tests {
		modes := []Flags{0, Unicode}
		if tt.strOnly {
			modes = []Flags{Unicode}
		}
		for _, mode := range modes {
			t.Run(fmt.Sprintf("%s/unicode=%v", name, mode != 0), func(t *testing.T) {
				m, err := Compile(tt.pattern, mode)
				if err != nil {
					t.Fatalf("Compile(%q) error = %v", tt.pattern, err)
				}
				for _, p := range tt.probes {
					if got := m.MatchString(p.input); got != p.want {
						t.Errorf("Compile(%q).MatchString(%q) = %v, want %v", tt.pattern, p.input, got, p.want)
					}
				}
			})
		}
	}
}

// TestCompileGroupNameErrors checks how an error message quotes a bad
// group name, as Python 3.13 does: repr in a str pattern, and ascii of the
// Latin-1 text in a bytes pattern, so a UTF-8 name shows as bytes.
func TestCompileGroupNameErrors(t *testing.T) {
	tests := map[string]struct {
		pattern string
		flags   Flags
		wantErr string
	}{
		"error: single quote in a name":    {pattern: "(?P<a'b>x)", flags: Unicode, wantErr: `bad character in group name "a'b"`},
		"error: digit then letter, str":    {pattern: "(?P<1\u00e9>x)", flags: Unicode, wantErr: "bad character in group name '1\u00e9'"},
		"error: digit then letter, bytes":  {pattern: "(?P<1\u00e9>x)", wantErr: `bad character in group name '1\xc3\xa9'`},
		"error: non-ASCII name in bytes":   {pattern: "(?P<\u00e9\u00e9x>a)", wantErr: `bad character in group name '\xc3\xa9\xc3\xa9x'`},
		"error: backreference name, bytes": {pattern: "(?P=1\u00e9)", wantErr: `bad character in group name '1\xc3\xa9'`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := Compile(tt.pattern, tt.flags)
			if err == nil {
				t.Fatalf("Compile(%q) = %v, want error %q", tt.pattern, m, tt.wantErr)
			}
			if !strings.HasSuffix(err.Error(), ": "+tt.wantErr) {
				t.Errorf("Compile(%q) error = %q, want it to end in %q", tt.pattern, err, tt.wantErr)
			}
		})
	}
}

// TestCompileCodePointEscapes checks \u and \U against Python 3.13. A str
// pattern takes exactly four or eight hex digits and a code point up to
// U+10FFFF; a bytes pattern has neither escape. wantStr empty means the
// str pattern compiles and matches probe; wantBytes is always an error.
func TestCompileCodePointEscapes(t *testing.T) {
	tests := map[string]struct {
		pattern   string
		probe     string
		wantStr   string
		wantBytes string
	}{
		"success: \\u":                 {pattern: `^\u0041$`, probe: "A", wantBytes: `bad escape \u`},
		"success: \\u in a class":      {pattern: `^[\u0041-\u0043]$`, probe: "B", wantBytes: `bad escape \u`},
		"success: \\u beside \\w":      {pattern: `^[\w\u00e9]$`, probe: "\u00e9", wantBytes: `bad escape \u`},
		"success: \\U":                 {pattern: `^\U0001F600$`, probe: "\U0001F600", wantBytes: `bad escape \U`},
		"success: \\U in a class":      {pattern: `^[\U00000041-\U00000043]$`, probe: "B", wantBytes: `bad escape \U`},
		"error: three digits":          {pattern: `\u004`, wantStr: `incomplete escape \u004`, wantBytes: `bad escape \u`},
		"error: no digits":             {pattern: `\u`, wantStr: `incomplete escape \u`, wantBytes: `bad escape \u`},
		"error: a letter after digits": {pattern: `\u004g`, wantStr: `incomplete escape \u004`, wantBytes: `bad escape \u`},
		"error: three digits in class": {pattern: `[\u004]`, wantStr: `incomplete escape \u004`, wantBytes: `bad escape \u`},
		"error: seven digits":          {pattern: `\U0000004`, wantStr: `incomplete escape \U0000004`, wantBytes: `bad escape \U`},
		"error: no digits after \\U":   {pattern: `\U`, wantStr: `incomplete escape \U`, wantBytes: `bad escape \U`},
		"error: beyond U+10FFFF":       {pattern: `\U00110000`, wantStr: `bad escape \U00110000`, wantBytes: `bad escape \U`},
	}
	for name, tt := range tests {
		for _, mode := range []Flags{0, Unicode} {
			t.Run(fmt.Sprintf("%s/unicode=%v", name, mode != 0), func(t *testing.T) {
				want := tt.wantBytes
				if mode == Unicode {
					want = tt.wantStr
				}
				m, err := Compile(tt.pattern, mode)
				if want == "" {
					if err != nil {
						t.Fatalf("Compile(%q) error = %v, Python accepts it", tt.pattern, err)
					}
					if !m.MatchString(tt.probe) {
						t.Errorf("Compile(%q).MatchString(%q) = false, want true", tt.pattern, tt.probe)
					}
					return
				}
				if err == nil {
					t.Fatalf("Compile(%q) = %v, want error %q", tt.pattern, m, want)
				}
				if !strings.HasSuffix(err.Error(), ": "+want) {
					t.Errorf("Compile(%q) error = %q, want it to end in %q", tt.pattern, err, want)
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
		"(?i)x(?=)|(?-i:[\u212a-\u212b])", `a*(?#c)?`, `(?x)a* ?`, `a*+a`, `(a|ab)++c`, `(?>a*)b`, `a*?+`, `\b*+`, `a{,2}`, `a{00,}`, `a{2,1}`, `\u0041`, `[\U0001F600]`, `\u004`, `[\w\x{41}]`, `[\d\p{L}]`, `\.js$`, `(a$)+`, `a\Z`, `\B`, `(?=a)(a+)+$`,
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
