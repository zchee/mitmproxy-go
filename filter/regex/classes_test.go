// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package regex

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

// classPoints are the subjects of TestCompileClasses. Besides the obvious
// cases they hold the code points where a Go engine's own class disagrees
// with Python: RE2's classes are ASCII-only, regexp2's \w also holds marks
// (U+0345), connector punctuation (U+203F) and the joiners (U+200D) but no
// letter-like numbers (U+00BD, U+2160), regexp2's \s lacks U+001C, and
// under IgnoreCase RE2 folds k and s into the Kelvin sign and the long s.
var classPoints = []rune{
	0x0663, // ARABIC-INDIC DIGIT THREE, Nd
	'é',
	0x2003, // EM SPACE, Zs
	0x00a0, // NO-BREAK SPACE, Zs
	0x212a, // KELVIN SIGN, Lu, folds to k
	'_',
	0x0345, // COMBINING GREEK YPOGEGRAMMENI, Mn, folds to iota
	0x203f, // UNDERTIE, Pc
	0x00bd, // VULGAR FRACTION ONE HALF, No
	0x2160, // ROMAN NUMERAL ONE, Nl
	0x200d, // ZERO WIDTH JOINER, Cf
	0x000b, // LINE TABULATION
	0x001c, // INFORMATION SEPARATOR FOUR, bidi class B
	0x0085, // NEXT LINE
	0x017f, // LATIN SMALL LETTER LONG S, folds to s
	'k',
	'5',
	' ',
}

// TestCompileClasses checks each class escape in str and bytes patterns on
// both engines, alone, alone in a class, in a class with another member,
// and as the complement of a negated class with another member, with and
// without IgnoreCase. A "1" in want means the pattern matches the code
// point of classPoints at that position. The values were recorded from
// Python 3.13 with re.search on str subjects for str patterns and on the
// UTF-8 encoding for bytes patterns; Python gave the same answer for every
// variant and for both case settings.
func TestCompileClasses(t *testing.T) {
	tests := map[string]struct {
		class      byte
		complement byte
		str        string
		bytes      string
	}{
		`success: \d`: {class: 'd', complement: 'D', str: "100000000000000010", bytes: "000000000000000010"},
		`success: \w`: {class: 'w', complement: 'W', str: "110011001100001110", bytes: "000001000000000110"},
		`success: \s`: {class: 's', complement: 'S', str: "001100000001110001", bytes: "000000000001000001"},
		`success: \D`: {class: 'D', complement: 'd', str: "011111111111111101", bytes: "111111111111111101"},
		`success: \W`: {class: 'W', complement: 'w', str: "001100110011110001", bytes: "111110111111111001"},
		`success: \S`: {class: 'S', complement: 's', str: "110011111110001110", bytes: "111111111110111110"},
	}
	modes := map[string]struct {
		flags Flags
		want  func(c, b string) string
	}{
		"str":   {flags: Unicode, want: func(s, _ string) string { return s }},
		"bytes": {flags: 0, want: func(_, b string) string { return b }},
	}
	for name, tt := range tests {
		variants := []string{
			fmt.Sprintf(`\%c`, tt.class),
			fmt.Sprintf(`[\%c]`, tt.class),
			fmt.Sprintf(`[\%c!]`, tt.class),
			fmt.Sprintf(`[^\%c!]`, tt.complement),
		}
		for modeName, mode := range modes {
			want := mode.want(tt.str, tt.bytes)
			for _, fold := range []Flags{0, IgnoreCase} {
				for _, v := range variants {
					// A lookahead sends the pattern to regexp2.
					for _, pattern := range []string{v, "(?=.)" + v} {
						backtracking := strings.HasPrefix(pattern, "(?=")
						t.Run(fmt.Sprintf("%s/%s/%q/fold=%v", name, modeName, pattern, fold != 0), func(t *testing.T) {
							flags := mode.flags | fold
							m, err := Compile(pattern, flags)
							if err != nil {
								t.Fatalf("Compile(%q, %v) error = %v", pattern, flags, err)
							}
							if got := IsBacktracking(m); got != backtracking {
								t.Errorf("IsBacktracking() = %v, want %v", got, backtracking)
							}
							var got strings.Builder
							for _, r := range classPoints {
								if m.MatchString(string(r)) {
									got.WriteByte('1')
								} else {
									got.WriteByte('0')
								}
							}
							if diff := gocmp.Diff(want, got.String()); diff != "" {
								t.Errorf("matches over classPoints mismatch (-want +got):\n%s", diff)
							}
						})
					}
				}
			}
		}
	}
}

// TestCompileClassEdges checks word boundaries and the places where the
// translation could misread the pattern. str and bytes are the results
// Python 3.13 gives for a str pattern on the subject and for a bytes
// pattern on its UTF-8 encoding, with and without re.IGNORECASE alike;
// strBT and bytesBT say whether the pattern runs on regexp2.
func TestCompileClassEdges(t *testing.T) {
	tests := map[string]struct {
		pattern        string
		input          string
		str, bytes     bool
		strBT, bytesBT bool
	}{
		`success: \b before x after é`:                        {pattern: `\bx`, input: "\u00e9x", str: false, bytes: true, strBT: true},
		`success: \B before x after é`:                        {pattern: `\Bx`, input: "\u00e9x", str: true, bytes: false, strBT: true, bytesBT: true},
		`success: \b after x before é`:                        {pattern: `x\b`, input: "x\u00e9", str: false, bytes: true, strBT: true},
		`success: \b around é`:                                {pattern: `\b`, input: "\u00e9", str: true, bytes: false, strBT: true},
		`success: \b around underscore`:                       {pattern: `\b`, input: "_", str: true, bytes: true, strBT: true},
		`success: \b before a combining mark`:                 {pattern: `a\b`, input: "a\u0345", str: true, bytes: true, strBT: true},
		`success: \b before a joiner`:                         {pattern: `a\b`, input: "a\u200d", str: true, bytes: true, strBT: true},
		`success: \b before connector punctuation`:            {pattern: `a\b`, input: "a\u203f", str: true, bytes: true, strBT: true},
		`success: \b in an empty input`:                       {pattern: `\b`, input: "", str: false, bytes: false, strBT: true},
		`success: \B in an empty input`:                       {pattern: `\B`, input: "", str: false, bytes: false, strBT: true, bytesBT: true},
		`success: \B in a space`:                              {pattern: `\B`, input: " ", str: true, bytes: true, strBT: true, bytesBT: true},
		`success: \b on regexp2 in a bytes pattern`:           {pattern: `(?=)\bx`, input: "\u00e9x", str: false, bytes: true, strBT: true, bytesBT: true},
		`success: \B on regexp2 in a bytes pattern`:           {pattern: `(?=)\Bx`, input: "\u00e9x", str: true, bytes: false, strBT: true, bytesBT: true},
		`success: escaped backslash before d`:                 {pattern: `\\d`, input: `\d`, str: true, bytes: true},
		`success: escaped backslash is not \d`:                {pattern: `\\d`, input: "5", str: false, bytes: false},
		`success: trailing dash in a class`:                   {pattern: `[\d-]`, input: "-", str: true, bytes: true},
		`success: \d in a class with a dash`:                  {pattern: `[\d-]`, input: "\u0663", str: true, bytes: false},
		`success: leading dash in a class`:                    {pattern: `[-\d]`, input: "-", str: true, bytes: true},
		`success: caret after a class escape`:                 {pattern: `[\w^]`, input: "^", str: true, bytes: true},
		`success: \w with a caret on é`:                       {pattern: `[\w^]`, input: "\u00e9", str: true, bytes: false},
		`success: leading bracket member`:                     {pattern: `[]\w]`, input: "]", str: true, bytes: true},
		`success: negated leading bracket member`:             {pattern: `[^]\w]`, input: "]", str: false, bytes: false},
		`success: negated bracket and \w on a mark`:           {pattern: `[^]\w]`, input: "\u0345", str: true, bytes: true},
		`success: any character idiom`:                        {pattern: `[\s\S]`, input: "\n", str: true, bytes: true},
		`success: empty class idiom`:                          {pattern: `[^\s\S]`, input: "a", str: false, bytes: false},
		`success: negated \w on a mark`:                       {pattern: `[^\w]`, input: "\u0345", str: true, bytes: true},
		`success: negated \s on em space`:                     {pattern: `[^\s]`, input: "\u2003", str: false, bytes: true},
		`success: counted \d`:                                 {pattern: `^\d{2}$`, input: "5\u0663", str: true, bytes: false},
		`success: lazy \d`:                                    {pattern: `^\d+?$`, input: "\u06635", str: true, bytes: false},
		`success: \d in a lookbehind`:                         {pattern: `(?<=\d)x`, input: "\u0663x", str: true, bytes: false, strBT: true, bytesBT: true},
		`success: range ending in a dash`:                     {pattern: `[!--\w]`, input: "-", str: true, bytes: true},
		`success: range ending in a dash on é`:                {pattern: `[!--\w]`, input: "\u00e9", str: true, bytes: false},
		`success: backspace in a class`:                       {pattern: `[\b\d]`, input: "\b", str: true, bytes: true, strBT: true, bytesBT: true},
		`success: hex escape in a class`:                      {pattern: `[\x41\d]`, input: "A", str: true, bytes: true},
		`success: scoped ignore case on Kelvin`:               {pattern: `(?i:[^\w.])`, input: "\u212a", str: false, bytes: true},
		`success: scoped case-sensitive negation`:             {pattern: `(?-i:[^\dk])`, input: "K", str: true, bytes: true},
		`success: scoped case-sensitive class`:                {pattern: `(?-i:[\dk])`, input: "K", str: false, bytes: false},
		`success: verbose comment holding [`:                  {pattern: "(?x) a # [\n \\d", input: "a\u0663", str: true, bytes: false, strBT: true, bytesBT: true},
		`success: comment group holding [`:                    {pattern: `(?#[)\d`, input: "\u0663", str: true, bytes: false},
		`success: comment group holding [ after a literal`:    {pattern: `x(?#[)\d`, input: "x\u0663", str: true, bytes: false},
		`success: scoped verbose comment`:                     {pattern: "(?x:a # [\n\\d)", input: "a\u0663", str: true, bytes: false, strBT: true, bytesBT: true},
		`success: \w under ignore case on Kelvin`:             {pattern: `(?i)\w`, input: "\u212a", str: true, bytes: false},
		`success: [^\W] under ignore case`:                    {pattern: `(?i)[^\W]`, input: "\u212a", str: true, bytes: false},
		`success: \w under ignore case on long s`:             {pattern: `(?i)\w`, input: "\u017f", str: true, bytes: false},
		`success: \W in a lookbehind on é`:                    {pattern: `(?<=\W)x`, input: "\u00e9x", str: false, bytes: true, strBT: true, bytesBT: true},
		`success: \W in a lookbehind on Kelvin`:               {pattern: `(?<=\W)x`, input: "\u212ax", str: false, bytes: true, strBT: true, bytesBT: true},
		`success: \W beside a folded alternative`:             {pattern: `(?=.)(?i:!|\W)`, input: "\u212a", str: false, bytes: true, strBT: true, bytesBT: true},
		`success: \W beside a folded alternative on dotted I`: {pattern: `(?=.)(?i:!|\W)`, input: "\u0130", str: false, bytes: true, strBT: true, bytesBT: true},
	}
	for name, tt := range tests {
		for _, fold := range []Flags{0, IgnoreCase} {
			for _, mode := range []Flags{0, Unicode} {
				want, wantBT := tt.bytes, tt.bytesBT
				if mode == Unicode {
					want, wantBT = tt.str, tt.strBT
				}
				t.Run(fmt.Sprintf("%s/unicode=%v/fold=%v", name, mode != 0, fold != 0), func(t *testing.T) {
					m, err := Compile(tt.pattern, mode|fold)
					if err != nil {
						t.Fatalf("Compile(%q) error = %v", tt.pattern, err)
					}
					if got := IsBacktracking(m); got != wantBT {
						t.Errorf("IsBacktracking() = %v, want %v", got, wantBT)
					}
					if got := m.MatchString(tt.input); got != want {
						t.Errorf("MatchString(%q) = %v, want %v", tt.input, got, want)
					}
					if got := m.Match([]byte(tt.input)); got != want {
						t.Errorf("Match(%q) = %v, want %v", tt.input, got, want)
					}
				})
			}
		}
	}
}

// TestCompileClassFoldScope checks that the members a class escape shares
// a class with fold case as the flags at that point say, while the escape
// itself never does. Python 3.13 gives these results for str and bytes
// patterns alike.
func TestCompileClassFoldScope(t *testing.T) {
	tests := map[string]struct {
		pattern string
		flags   Flags
		input   string
		want    bool
	}{
		"success: negated class folds k under ignore case":      {pattern: `[^\dk]`, flags: IgnoreCase, input: "K", want: false},
		"success: negated class keeps case without ignore case": {pattern: `[^\dk]`, input: "K", want: true},
		"success: scoped ignore case folds k":                   {pattern: `(?i:[^\dk])`, input: "K", want: false},
		"success: scoped case-sensitive group inside ignore":    {pattern: `(?-i:[^\dk])`, flags: IgnoreCase, input: "K", want: true},
		"success: flags restored after the scoped group":        {pattern: `(?-i:x)[^\dk]`, flags: IgnoreCase, input: "xK", want: false},
	}
	for name, tt := range tests {
		for _, mode := range []Flags{0, Unicode} {
			t.Run(fmt.Sprintf("%s/unicode=%v", name, mode != 0), func(t *testing.T) {
				m, err := Compile(tt.pattern, tt.flags|mode)
				if err != nil {
					t.Fatalf("Compile(%q) error = %v", tt.pattern, err)
				}
				if IsBacktracking(m) {
					t.Errorf("Compile(%q) fell back to regexp2", tt.pattern)
				}
				if got := m.MatchString(tt.input); got != tt.want {
					t.Errorf("MatchString(%q) = %v, want %v", tt.input, got, tt.want)
				}
			})
		}
	}
}

// TestCompileBracketInClass checks that a [ inside a character class is a
// literal member, as in Python, on both engines: RE2 would otherwise read
// [:alpha:] as a POSIX class and regexp2 would read -[ as the start of a
// class subtraction. match lists the subjects Python 3.13 finds a match
// in and miss those it does not, the same for str and bytes patterns with
// and without re.IGNORECASE.
func TestCompileBracketInClass(t *testing.T) {
	tests := map[string]struct {
		pattern     string
		match, miss []string
	}{
		"success: what looks like a POSIX class":        {pattern: `[[:alpha:]]`, match: []string{"a]", ":]", "[]"}, miss: []string{"b"}},
		`success: a POSIX look-alike beside \d`:         {pattern: `x[[:digit:]\d]`, match: []string{"x:5]", "xd0]", "x[1]"}, miss: []string{"x5"}},
		`success: a range ending in [ beside \w`:        {pattern: `[\w.-[]`, match: []string{"[", ".", "A"}, miss: []string{"-", `\`}},
		`success: a [ before a trailing dash beside \d`: {pattern: `[\d[-]`, match: []string{"[", "-"}, miss: []string{`\`}},
		`success: a [ in a negated class beside \d`:     {pattern: `[^[\d]`, match: []string{"a"}, miss: []string{"[", "5"}},
		"success: a [ alone":                            {pattern: `[[]`, match: []string{"["}, miss: []string{"a"}},
		"success: a [ after another member":             {pattern: `[a[]`, match: []string{"[", "a"}},
		"success: a [ after a leading bracket member":   {pattern: `[]a[]`, match: []string{"[", "]"}},
	}
	for name, tt := range tests {
		for _, flags := range []Flags{0, Unicode, IgnoreCase, Unicode | IgnoreCase} {
			// A lookahead sends the pattern to regexp2.
			for _, pattern := range []string{tt.pattern, "(?=.)" + tt.pattern} {
				t.Run(fmt.Sprintf("%s/%q/flags=%d", name, pattern, flags), func(t *testing.T) {
					m, err := Compile(pattern, flags)
					if err != nil {
						t.Fatalf("Compile(%q) error = %v", pattern, err)
					}
					for _, in := range tt.match {
						if !m.MatchString(in) {
							t.Errorf("MatchString(%q) = false, want true", in)
						}
					}
					for _, in := range tt.miss {
						if m.MatchString(in) {
							t.Errorf("MatchString(%q) = true, want false", in)
						}
					}
				})
			}
		}
	}
}

// TestCompileOverlapDoesNotBacktrack checks that what the translation emits
// for regexp2 never offers two ways to match the same text: a class whose
// members overlap its class escape, such as [\w_], and a run of \B. Under a
// quantifier, or in a sequence, every extra way multiplies the work on a
// near miss, so the match would run into MatchTimeout and report no match.
// want is what Python 3.13 gives with re.search, str patterns on str
// subjects and bytes patterns on bytes; every case runs on regexp2.
func TestCompileOverlapDoesNotBacktrack(t *testing.T) {
	tests := map[string]struct {
		pattern string
		flags   Flags
		input   string
		want    bool
	}{
		`success: \b[\w_]+Z after a URL, str, ignore case`: {
			pattern: `\b[\w_]+Z`, flags: Unicode | IgnoreCase,
			input: "http://example.com/" + strings.Repeat("_", 30) + "!aZ", want: true,
		},
		`success: [\w_]+ before a lookahead, bytes, ignore case`: {
			pattern: `[\w_]+(?=Z)`, flags: IgnoreCase,
			input: strings.Repeat("_", 30) + "!aZ", want: true,
		},
		`success: [\w_]+ before a lookahead, str`: {
			pattern: `[\w_]+(?=Z)`, flags: Unicode,
			input: strings.Repeat("_", 30) + "!aZ", want: true,
		},
		`success: [_\w.-]+, str, ignore case`: {
			pattern: `[_\w.-]+(?=Z)`, flags: Unicode | IgnoreCase,
			input: strings.Repeat("_.-", 10) + "!aZ", want: true,
		},
		`success: [\da-f0-9]+, bytes`: {
			pattern: `[\da-f0-9]+(?=Z)`,
			input:   strings.Repeat("1", 30) + "!aZ", want: true,
		},
		`success: [\sa ]+, str`: {
			pattern: `[\sa ]+(?=Z)`, flags: Unicode,
			input: strings.Repeat(" ", 30) + "!aZ", want: true,
		},
		`success: [\W!]+, str`: {
			pattern: `[\W!]+(?=Z)`, flags: Unicode,
			input: strings.Repeat("!", 30) + "a!Z", want: true,
		},
		`success: scoped ignore case around [\d1]+, bytes`: {
			pattern: `(?i:[\d1]+)(?=Z)`,
			input:   strings.Repeat("1", 30) + "!aZ", want: false,
		},
		`success: a run of \B between spaces, str`: {
			pattern: " " + strings.Repeat(`\B`, 25) + "x", flags: Unicode,
			input: "   ", want: false,
		},
		`success: a run of \B between spaces, bytes`: {
			pattern: " " + strings.Repeat(`\B`, 25) + "x",
			input:   "   ", want: false,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := Compile(tt.pattern, tt.flags)
			if err != nil {
				t.Fatalf("Compile(%q) error = %v", tt.pattern, err)
			}
			if !IsBacktracking(m) {
				t.Fatalf("Compile(%q) runs on RE2; the case needs regexp2", tt.pattern)
			}
			start := time.Now()
			got := m.MatchString(tt.input)
			// A linear match takes microseconds; the bound leaves room
			// for the race detector and stays well below MatchTimeout.
			if elapsed := time.Since(start); elapsed > MatchTimeout/4 {
				t.Errorf("MatchString(%q) took %v; the translation backtracks", tt.input, elapsed)
			}
			if got != tt.want {
				t.Errorf("MatchString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestTranslateClassesLinear checks that the translation reads a pattern
// in one pass. Looking ahead to the end of the pattern from every group
// takes seconds on these 2 MB patterns; one pass takes milliseconds.
func TestTranslateClassesLinear(t *testing.T) {
	tests := map[string]struct {
		unit string
	}{
		"success: lookaheads":            {unit: "(?=a)"},
		"success: unclosed flag letters": {unit: "(?i"},
		"success: named groups":          {unit: "(?P<n>a)"},
		"success: comments":              {unit: "a(?#)"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			body := strings.Repeat(tt.unit, 2<<20/len(tt.unit))
			start := time.Now()
			if _, err := translateClasses(body, Unicode, true, false); err != nil {
				t.Fatalf("translateClasses() error = %v", err)
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Errorf("translateClasses() on %d bytes took %v; the scan is not linear", len(body), elapsed)
			}
		})
	}
}

// BenchmarkMatchOverlappingClass matches \b[\w_]+Z on a URL followed by a
// run of underscores that ends in a near miss. The time per byte stays the
// same as the run grows only if the regexp2 translation of [\w_] gives the
// engine one way to match each underscore.
func BenchmarkMatchOverlappingClass(b *testing.B) {
	m, err := Compile(`\b[\w_]+Z`, Unicode|IgnoreCase)
	if err != nil {
		b.Fatal(err)
	}
	for _, n := range []int{1_000, 10_000} {
		input := "http://example.com/" + strings.Repeat("_", n) + "!aZ"
		b.Run(fmt.Sprintf("run=%d", n), func(b *testing.B) {
			b.SetBytes(int64(len(input)))
			for b.Loop() {
				if !m.MatchString(input) {
					b.Fatal("no match")
				}
			}
		})
	}
}

// TestCompileUserRangeCaseTable pins the regexp2 difference listed in
// docs/compat.md: regexp2 lowercases a class range with a case table that
// lacks some case pairs, so a folded range misses such a letter and a
// case-sensitive range cannot start a match at one when the pattern can
// also start with a case-insensitive part. Python 3.13 finds a match in
// every case below with a str pattern; the cases marked documented differ.
// The Go engines behave the same in both modes.
func TestCompileUserRangeCaseTable(t *testing.T) {
	const kelvin = "\u212a"
	tests := map[string]struct {
		pattern      string
		input        string
		backtracking bool
		want         bool
	}{
		"success: range at the start on regexp2 misses (documented)": {pattern: `(?i)x(?=)|(?-i:[\x{212a}-\x{212b}])`, input: kelvin, backtracking: true, want: false},
		"success: single character at the start on regexp2":          {pattern: `(?i)x(?=)|(?-i:[\x{212a}])`, input: kelvin, backtracking: true, want: true},
		"success: range after a literal on regexp2":                  {pattern: `(?=)a(?:(?i:x)|[\x{212a}-\x{212b}])`, input: "a" + kelvin, backtracking: true, want: true},
		"success: range at the start on RE2":                         {pattern: `(?i)x|(?-i:[\x{212a}-\x{212b}])`, input: kelvin, want: true},
		"success: folded range on regexp2 misses (documented)":       {pattern: `(?i)(?=)[\x{13a0}-\x{13a1}]`, input: "\u13a0", backtracking: true, want: false},
		"success: folded single character on regexp2":                {pattern: `(?i)(?=)\x{13a0}`, input: "\uab70", backtracking: true, want: true},
		"success: folded range on RE2":                               {pattern: `(?i)[\x{13a0}-\x{13a1}]`, input: "\uab70", want: true},
	}
	for name, tt := range tests {
		for _, mode := range []Flags{0, Unicode} {
			t.Run(fmt.Sprintf("%s/unicode=%v", name, mode != 0), func(t *testing.T) {
				m, err := Compile(tt.pattern, mode)
				if err != nil {
					t.Fatalf("Compile(%q) error = %v", tt.pattern, err)
				}
				if got := IsBacktracking(m); got != tt.backtracking {
					t.Errorf("IsBacktracking() = %v, want %v", got, tt.backtracking)
				}
				if got := m.MatchString(tt.input); got != tt.want {
					t.Errorf("MatchString(%+q) = %v, want %v", tt.input, got, tt.want)
				}
			})
		}
	}
}

// TestCompileClassRangeError checks that a range with a class escape at
// either end is an error, as Python reports "bad character range".
func TestCompileClassRangeError(t *testing.T) {
	tests := map[string]struct {
		pattern string
	}{
		"error: class escape starts a range": {pattern: `[\w-a]`},
		"error: class escape ends a range":   {pattern: `[a-\w]`},
		"error: two class escapes":           {pattern: `[\w-\d]`},
		"error: dash starts a range":         {pattern: `[--\w]`},
	}
	for name, tt := range tests {
		for _, mode := range []Flags{0, Unicode} {
			t.Run(fmt.Sprintf("%s/unicode=%v", name, mode != 0), func(t *testing.T) {
				m, err := Compile(tt.pattern, mode)
				if err == nil {
					t.Fatalf("Compile(%q) = %v, want error", tt.pattern, m)
				}
				if !strings.Contains(err.Error(), "bad character range") || !strings.Contains(err.Error(), strconv.Quote(tt.pattern)) {
					t.Errorf("error %q does not report a bad range in %q", err, tt.pattern)
				}
			})
		}
	}
}

func TestRuneSet(t *testing.T) {
	tests := map[string]struct {
		got  runeSet
		want runeSet
	}{
		"success: normalize sorts and merges touching ranges": {
			got:  runeSet{'d', 'f', 'a', 'c', 'x', 'x'}.normalize(),
			want: runeSet{'a', 'f', 'x', 'x'},
		},
		"success: union merges overlaps": {
			got:  runeSet{'a', 'm'}.union(runeSet{'k', 'z', '0', '9'}),
			want: runeSet{'0', '9', 'a', 'z'},
		},
		"success: negate of the empty set is everything": {
			got:  runeSet{}.negate(),
			want: runeSet{0, 0x10ffff},
		},
		"success: negate of everything is empty": {
			got:  runeSet{0, 0x10ffff}.negate(),
			want: runeSet{},
		},
		"success: negate keeps the edges": {
			got:  runeSet{0, 9, 'a', 'a'}.negate(),
			want: runeSet{10, 'a' - 1, 'a' + 1, 0x10ffff},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, tt.got); diff != "" {
				t.Errorf("runeSet mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRuneSetString(t *testing.T) {
	tests := map[string]struct {
		set  runeSet
		want string
	}{
		"success: single runes and ranges":   {set: runeSet{'0', '9', '_', '_'}, want: `[\x{30}-\x{39}\x{5f}]`},
		"success: empty set matches nothing": {set: runeSet{}, want: `[^\x{0}-\x{10ffff}]`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tt.set.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func BenchmarkCompileClass(b *testing.B) {
	benchmarks := map[string]struct {
		pattern string
		flags   Flags
	}{
		"bytes":   {pattern: `^content-type: \w+/\w+`, flags: IgnoreCase | Multiline},
		"unicode": {pattern: `/api/v\d+/\w+`, flags: IgnoreCase | Unicode},
	}
	for name, bm := range benchmarks {
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				if _, err := Compile(bm.pattern, bm.flags); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestCompileCharsetFlags checks the inline flags a, u and L. want and
// wantFlags are what Python 3.13 gives with re.search under re.IGNORECASE:
// a str pattern compiled with re.ASCII loses re.UNICODE from its flags.
func TestCompileCharsetFlags(t *testing.T) {
	tests := map[string]struct {
		pattern      string
		flags        Flags
		input        string
		want         bool
		wantFlags    Flags
		backtracking bool
	}{
		"success: global a makes \\d ASCII":     {pattern: `(?a)\d`, flags: Unicode, input: "\u0663", want: false, wantFlags: IgnoreCase},
		"success: scoped a makes \\d ASCII":     {pattern: `(?a:\d)`, flags: Unicode, input: "\u0663", want: false, wantFlags: IgnoreCase | Unicode},
		"success: scoped a ends with its group": {pattern: `(?a:\d)\d`, flags: Unicode, input: "5\u0663", want: true, wantFlags: IgnoreCase | Unicode},
		"success: global u keeps \\d Unicode":   {pattern: `(?u)\d`, flags: Unicode, input: "\u0663", want: true, wantFlags: IgnoreCase | Unicode},
		"success: global a makes \\w ASCII":     {pattern: `(?a)\w`, flags: Unicode, input: "\u00e9", want: false, wantFlags: IgnoreCase},
		"success: global a keeps \\b on RE2":    {pattern: `(?a)\bx`, flags: Unicode, input: "\u00e9x", want: true, wantFlags: IgnoreCase},
		"success: scoped a keeps \\b on RE2":    {pattern: `(?a:\b)x`, flags: Unicode, input: "\u00e9x", want: true, wantFlags: IgnoreCase | Unicode},
		"success: global a in a negated class":  {pattern: `(?a)[^\w.]`, flags: Unicode, input: "\u00e9", want: true, wantFlags: IgnoreCase},
		"success: global a makes \\s ASCII":     {pattern: `(?a)\s`, flags: Unicode, input: "\u2003", want: false, wantFlags: IgnoreCase},
		"success: global a after another group": {pattern: `(?i)(?a)\d`, flags: Unicode, input: "\u0663", want: false, wantFlags: IgnoreCase},
		"success: scoped u inside scoped a":     {pattern: `(?a:(?u:\w))`, flags: Unicode, input: "\u00e9", want: true, wantFlags: IgnoreCase | Unicode},
		"success: scoped a with other flags":    {pattern: `(?ai-s:\w)`, flags: Unicode, input: "\u00e9", want: false, wantFlags: IgnoreCase | Unicode},
		"success: scoped a between other flags": {pattern: `(?ias:\w)`, flags: Unicode, input: "\u00e9", want: false, wantFlags: IgnoreCase | Unicode},
		"success: scoped a after other flags":   {pattern: `(?sia:\w)`, flags: Unicode, input: "a", want: true, wantFlags: IgnoreCase | Unicode},
		"success: scoped u between other flags": {pattern: `(?ius-m:\w)`, flags: Unicode, input: "\u00e9", want: true, wantFlags: IgnoreCase | Unicode},
		"success: scoped a between, bytes":      {pattern: `(?sai:x)`, input: "X", want: true, wantFlags: IgnoreCase},
		"success: scoped L between, bytes":      {pattern: `(?iLs:x)`, input: "X", want: true, wantFlags: IgnoreCase},
		// CPython's re.search misses this match, because it computes where
		// a match can start with the global flags; re.match finds it, and
		// the scoped flag is what the pattern says.
		"success: scoped u under global a is Unicode": {pattern: `(?a)(?u:\d)`, flags: Unicode, input: "\u0663", want: true, wantFlags: IgnoreCase},
		"success: global a with \\B":                  {pattern: `(?a)\B`, flags: Unicode, input: "\u00e9", want: true, wantFlags: IgnoreCase, backtracking: true},
		"success: global a in a bytes pattern":        {pattern: `(?a)\d`, input: "5", want: true, wantFlags: IgnoreCase},
		"success: scoped a in a bytes pattern":        {pattern: `(?a:\d)`, input: "5", want: true, wantFlags: IgnoreCase},
		"success: global L in a bytes pattern":        {pattern: `(?L)\d`, input: "5", want: true, wantFlags: IgnoreCase},
		"success: scoped L in a bytes pattern":        {pattern: `(?L:\w)`, input: "\u00e9", want: false, wantFlags: IgnoreCase},
		"success: global L keeps ASCII \\w":           {pattern: `(?L)\w`, input: "a", want: true, wantFlags: IgnoreCase},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := Compile(tt.pattern, tt.flags|IgnoreCase)
			if err != nil {
				t.Fatalf("Compile(%q) error = %v", tt.pattern, err)
			}
			if got := IsBacktracking(m); got != tt.backtracking {
				t.Errorf("IsBacktracking() = %v, want %v", got, tt.backtracking)
			}
			if got := m.Flags(); got != tt.wantFlags {
				t.Errorf("Flags() = %d, want %d", got, tt.wantFlags)
			}
			if got := m.MatchString(tt.input); got != tt.want {
				t.Errorf("MatchString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestCompileCharsetFlagErrors checks that the inline flags a, u and L are
// rejected where Python 3.13 rejects them, with Python's message.
func TestCompileCharsetFlagErrors(t *testing.T) {
	tests := map[string]struct {
		pattern string
		flags   Flags
		wantErr string
	}{
		"error: global L in a str pattern":    {pattern: `(?L)\d`, flags: Unicode, wantErr: "cannot use 'L' flag with a str pattern"},
		"error: scoped L in a str pattern":    {pattern: `(?L:\d)`, flags: Unicode, wantErr: "cannot use 'L' flag with a str pattern"},
		"error: a and u in one group":         {pattern: `(?au)\d`, flags: Unicode, wantErr: "flags 'a', 'u' and 'L' are incompatible"},
		"error: a and u in one scoped group":  {pattern: `(?au:\d)`, flags: Unicode, wantErr: "flags 'a', 'u' and 'L' are incompatible"},
		"error: a turned off":                 {pattern: `(?-a:\d)`, flags: Unicode, wantErr: "cannot turn off flags 'a', 'u' and 'L'"},
		"error: u turned off":                 {pattern: `(?-u:\d)`, flags: Unicode, wantErr: "cannot turn off flags 'a', 'u' and 'L'"},
		"error: a and u in two global groups": {pattern: `(?a)(?u)\d`, flags: Unicode, wantErr: "ASCII and UNICODE flags are incompatible"},
		"error: L after a in a str pattern":   {pattern: `(?a)(?L)\d`, flags: Unicode, wantErr: "cannot use 'L' flag with a str pattern"},
		"error: global u in a bytes pattern":  {pattern: `(?u)\d`, wantErr: "cannot use 'u' flag with a bytes pattern"},
		"error: scoped u in a bytes pattern":  {pattern: `(?u:\d)`, wantErr: "cannot use 'u' flag with a bytes pattern"},
		"error: a and L in one group":         {pattern: `(?aL)\d`, wantErr: "flags 'a', 'u' and 'L' are incompatible"},
		"error: a and L in two global groups": {pattern: `(?a)(?L)\d`, wantErr: "ASCII and LOCALE flags are incompatible"},
		"error: L turned off":                 {pattern: `(?-L:\d)`, wantErr: "cannot turn off flags 'a', 'u' and 'L'"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := Compile(tt.pattern, tt.flags)
			if err == nil {
				t.Fatalf("Compile(%q) = %v, want error", tt.pattern, m)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Compile(%q) error = %q, want it to contain %q", tt.pattern, err, tt.wantErr)
			}
		})
	}
}
