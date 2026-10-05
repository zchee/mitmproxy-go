// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package regex

import (
	"cmp"
	"errors"
	"fmt"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// runeSet is a set of runes stored as sorted, disjoint, non-adjacent
// inclusive ranges in lo, hi pairs, the layout of syntax.Regexp.Rune.
type runeSet []rune

// normalize sorts the ranges of s and merges those that overlap or touch.
func (s runeSet) normalize() runeSet {
	pairs := make([][2]rune, 0, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		pairs = append(pairs, [2]rune{s[i], s[i+1]})
	}
	slices.SortFunc(pairs, func(a, b [2]rune) int { return cmp.Compare(a[0], b[0]) })
	out := make(runeSet, 0, len(s))
	for _, p := range pairs {
		if n := len(out); n > 0 && p[0] <= out[n-1]+1 {
			out[n-1] = max(out[n-1], p[1])
			continue
		}
		out = append(out, p[0], p[1])
	}
	return out
}

func (s runeSet) union(o runeSet) runeSet {
	return slices.Concat(s, o).normalize()
}

// negate returns every rune up to unicode.MaxRune that s does not hold. s
// must be normalized.
func (s runeSet) negate() runeSet {
	out := make(runeSet, 0, len(s)+2)
	next := rune(0)
	for i := 0; i < len(s); i += 2 {
		if s[i] > next {
			out = append(out, next, s[i]-1)
		}
		next = s[i+1] + 1
	}
	if next <= unicode.MaxRune {
		out = append(out, next, unicode.MaxRune)
	}
	return out
}

// String renders s as a character class both RE2 and regexp2 parse, with
// every rune as a \x{...} escape so that no rune needs quoting.
func (s runeSet) String() string {
	if len(s) == 0 {
		return `[^\x{0}-\x{10ffff}]`
	}
	var b strings.Builder
	b.Grow(len(s)*10 + 2)
	b.WriteByte('[')
	for i := 0; i < len(s); i += 2 {
		writeRuneEscape(&b, s[i])
		if s[i+1] != s[i] {
			b.WriteByte('-')
			writeRuneEscape(&b, s[i+1])
		}
	}
	b.WriteByte(']')
	return b.String()
}

func writeRuneEscape(b *strings.Builder, r rune) {
	b.WriteString(`\x{`)
	b.WriteString(strconv.FormatInt(int64(r), 16))
	b.WriteByte('}')
}

// classExpr is a class to emit: the runes it holds and, when the class
// escapes it comes from allow, a bracket expression built from Unicode
// property classes. Both engines read \p{...} from Go's unicode tables, so
// the two forms hold the same runes; the property form is much cheaper,
// because regexp2 tests a class written as ranges one range at a time, and
// the Unicode \w has hundreds of them.
type classExpr struct {
	set  runeSet
	text string // the property form, or "" to write set out as ranges
	// lowerOpen says that set holds a rune but not its lowercase; see
	// backtrackExact.
	lowerOpen bool
}

func newClassExpr(set runeSet, text string) classExpr {
	e := classExpr{set: set, text: text}
	for _, r := range lowerMapped() {
		if set.contains(r) && !set.contains(unicode.ToLower(r)) {
			e.lowerOpen = true
			break
		}
	}
	return e
}

func (c classExpr) String() string {
	if c.text != "" {
		return c.text
	}
	return c.set.String()
}

func (c classExpr) negate() classExpr {
	text := c.text
	if body, ok := strings.CutPrefix(text, "[^"); ok {
		text = "[" + body
	} else if text != "" {
		text = "[^" + text[1:]
	}
	return newClassExpr(c.set.negate(), text)
}

// exact renders c as a class that matches exactly c whatever the case
// flags around it. Python never folds the case of \d, \w or \s, while both
// Go engines would fold the class: under IgnoreCase, RE2 adds the Kelvin
// sign to [A-Za-z].
func (c classExpr) exact() string {
	return "(?-i:" + c.String() + ")"
}

// backtrackExact renders c for regexp2 as exact does, working around how
// regexp2 finds where a match can start. It collects the characters every
// alternative can start with and, when any of them is case-insensitive,
// lowercases each input character before looking it up in that union. A
// case-sensitive set holding a character but not its lowercase, such as
// the Kelvin sign without k in the \W of a bytes pattern, then never
// starts a match. Such a set becomes a lookahead followed by any
// character, which leaves the start unconstrained.
func (c classExpr) backtrackExact() string {
	if c.lowerOpen {
		return `(?:(?=` + c.exact() + `)(?s:.))`
	}
	return c.exact()
}

// contains reports whether s holds r.
func (s runeSet) contains(r rune) bool {
	i, found := slices.BinarySearch(s, r)
	return found || i%2 == 1
}

// lowerMapped lists the runes that unicode.ToLower changes.
var lowerMapped = sync.OnceValue(func() []rune {
	var rs []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.ToLower(r) != r {
			rs = append(rs, r)
		}
	}
	return rs
})

func tableSet(tables []*unicode.RangeTable, extra ...rune) runeSet {
	var s runeSet
	for _, t := range tables {
		for _, r := range t.R16 {
			s = appendStrided(s, rune(r.Lo), rune(r.Hi), rune(r.Stride))
		}
		for _, r := range t.R32 {
			s = appendStrided(s, rune(r.Lo), rune(r.Hi), rune(r.Stride))
		}
	}
	return slices.Concat(s, extra).normalize()
}

func appendStrided(s runeSet, lo, hi, stride rune) runeSet {
	if stride == 1 {
		return append(s, lo, hi)
	}
	for r := lo; r <= hi; r += stride {
		s = append(s, r, r)
	}
	return s
}

// Shorthand class indexes into the tables below.
const (
	classDigit = iota
	classWord
	classSpace
)

// classSets holds the sets behind \d, \w and \s, indexed by
// [unicode][class].
//
// For a str pattern CPython's sre defines them with the str predicates
// (Modules/_sre/sre.c): \d is str.isdecimal, which is exactly the Unicode
// category Nd; \w is str.isalnum or "_", which is the categories L, Nd, Nl
// and No; \s is str.isspace, which is the category Zs, the bidirectional
// classes WS, B and S (U+0009 to U+000D, U+001C to U+001F, U+0085, U+2028,
// U+2029). For a bytes pattern they are ASCII only: [0-9], [0-9A-Za-z_]
// and [\t\n\v\f\r ].
//
// The Unicode sets come from Go's unicode tables, so they follow its
// Unicode version. TestClassSetsMatchPython checks every code point
// against the sets recorded from the pinned Python.
var classSets = sync.OnceValue(func() (sets [2][3]runeSet) {
	sets[0][classDigit] = runeSet{'0', '9'}
	sets[0][classWord] = runeSet{'0', '9', 'A', 'Z', '_', '_', 'a', 'z'}
	sets[0][classSpace] = runeSet{'\t', '\r', ' ', ' '}
	sets[1][classDigit] = tableSet([]*unicode.RangeTable{unicode.Nd})
	sets[1][classWord] = tableSet([]*unicode.RangeTable{unicode.L, unicode.Nd, unicode.Nl, unicode.No}, '_', '_')
	sets[1][classSpace] = tableSet([]*unicode.RangeTable{unicode.Zs}, '\t', '\r', 0x1c, 0x1f, 0x85, 0x85, 0x2028, 0x2029)
	return sets
})

// classProps holds the bodies of the property forms of classSets, without
// brackets, indexed the same way. Runes are written as \x{...} because a
// space would be dropped in verbose mode by regexp2.
var classProps = [2][3]string{
	{`0-9`, `0-9A-Za-z_`, `\x{9}-\x{d}\x{20}`},
	{`\p{Nd}`, `\p{L}\p{Nd}\p{Nl}\p{No}_`, `\x{9}-\x{d}\x{1c}-\x{1f}\x{85}\p{Zs}\x{2028}\x{2029}`},
}

// singleExprs caches shorthandExpr for one class escape, indexed by
// [unicode][class] and then plain or negated.
var singleExprs = sync.OnceValue(func() (e [2][3][2]classExpr) {
	for u, uni := range []bool{false, true} {
		for i, c := range []byte{'d', 'w', 's'} {
			e[u][i][0] = buildShorthandExpr([]byte{c}, uni)
			e[u][i][1] = buildShorthandExpr([]byte{c - 'a' + 'A'}, uni)
		}
	}
	return e
})

// shorthandExpr returns the class a sequence of class escapes stands for
// together, such as \d or \W alone or the \s\S of [\s\S]. The property
// form covers escapes that are all positive, or a single negated one.
func shorthandExpr(shorts []byte, uni bool) classExpr {
	if len(shorts) != 1 {
		return buildShorthandExpr(shorts, uni)
	}
	u, neg := 0, 0
	if uni {
		u = 1
	}
	if c := shorts[0]; 'A' <= c && c <= 'Z' {
		neg = 1
	}
	return singleExprs()[u][classIndex(shorts[0])][neg]
}

func buildShorthandExpr(shorts []byte, uni bool) classExpr {
	var (
		set       runeSet
		pos, negs []string
	)
	u := 0
	if uni {
		u = 1
	}
	for _, c := range shorts {
		set = set.union(shorthandSet(c, uni))
		body := classProps[u][classIndex(c)]
		if 'A' <= c && c <= 'Z' {
			negs = append(negs, body)
		} else {
			pos = append(pos, body)
		}
	}
	var text string
	switch {
	case len(negs) == 0:
		text = "[" + strings.Join(pos, "") + "]"
	case len(negs) == 1 && len(pos) == 0:
		text = "[^" + negs[0] + "]"
	}
	return newClassExpr(set, text)
}

func classIndex(c byte) int {
	switch c {
	case 'd', 'D':
		return classDigit
	case 'w', 'W':
		return classWord
	}
	return classSpace
}

// shorthandSet returns the set a class escape such as \d or \W stands for.
func shorthandSet(c byte, uni bool) runeSet {
	u := 0
	if uni {
		u = 1
	}
	s := classSets()[u][classIndex(c)]
	if 'A' <= c && c <= 'Z' {
		return s.negate()
	}
	return s
}

func isShorthand(c byte) bool {
	switch c {
	case 'd', 'D', 'w', 'W', 's', 'S':
		return true
	}
	return false
}

// boundary returns \b or \B for regexp2 as lookarounds on the word set of
// the mode. Python's \B does not match in an empty input (CPython 3.13
// sre: SRE_AT_NON_BOUNDARY fails when the input is empty), while a plain
// "neither side is a word character" would. No two branches can hold at
// the same position, so that regexp2 never retries a boundary that has
// already matched.
func boundary(c byte, uni bool) string {
	w := shorthandExpr([]byte{'w'}, uni).String()
	if c == 'b' {
		return "(?-i:(?:(?<=" + w + ")(?!" + w + ")|(?<!" + w + ")(?=" + w + ")))"
	}
	const anyRune = `[\x{0}-\x{10ffff}]`
	return "(?-i:(?:(?<=" + w + ")(?=" + w + ")|(?<!" + w + ")(?!" + w + ")(?:(?<=" + anyRune + ")|(?<!" + anyRune + ")(?=" + anyRune + "))))"
}

// hasScannedEscape reports whether pattern contains an escape the scanner
// rewrites or refuses: \d, \D, \w, \W, \s, \S, \b, \B, \u, \U, \p, \P or
// \x{, possibly inside a character class.
func hasScannedEscape(pattern string) bool {
	for i := 0; i+1 < len(pattern); i++ {
		if pattern[i] != '\\' {
			continue
		}
		i++
		if c := pattern[i]; isShorthand(c) || c == 'b' || c == 'B' || c == 'u' || c == 'U' || foreignEscape(pattern, i-1) != nil {
			return true
		}
	}
	return false
}

// foreignEscape returns Python's error for the escape that starts with the
// backslash at src[i], with i+1 < len(src), when both Go engines accept it
// and Python does not: the property classes \p and \P, and \x{...}, where
// Python reads \x and then no hex digit.
func foreignEscape(src string, i int) error {
	switch e := src[i+1]; {
	case e == 'p' || e == 'P':
		return fmt.Errorf(`bad escape \%c`, e)
	case e == 'x' && i+2 < len(src) && src[i+2] == '{':
		return errors.New(`incomplete escape \x`)
	}
	return nil
}

// codePointEscape reads the \u or \U escape that starts with the backslash
// at src[i], with i+1 < len(src), and returns it as \x{...}, which both
// engines read, and the index after it: RE2 knows neither escape and
// regexp2 lacks \U. Like Python it takes exactly four or eight hex digits
// and a code point up to U+10FFFF in a str pattern, and rejects both
// escapes in a bytes pattern.
func codePointEscape(src string, i int, str bool) (string, int, error) {
	e := src[i+1]
	if !str {
		return "", 0, fmt.Errorf(`bad escape \%c`, e)
	}
	n := 4
	if e == 'U' {
		n = 8
	}
	j := i + 2
	for j < len(src) && j-i-2 < n && isHex(src[j]) {
		j++
	}
	if j-i-2 < n {
		return "", 0, fmt.Errorf("incomplete escape %s", src[i:j])
	}
	if v, err := strconv.ParseUint(src[i+2:j], 16, 32); err != nil || v > unicode.MaxRune {
		return "", 0, fmt.Errorf("bad escape %s", src[i:j])
	}
	return `\x{` + src[i+2:j] + `}`, j, nil
}

// repeatText returns the {m,n} repeat s, which braceRepeat has found, in a
// form both engines read as Python does: they take {,n} and {,} as literal
// text, and RE2 also a count with a leading zero, where Python repeats from
// 0. It rejects a minimum above the maximum with Python's message.
func repeatText(s string) (string, error) {
	count := func(d string) string {
		if d = strings.TrimLeft(d, "0"); d == "" {
			return "0"
		}
		return d
	}
	lo, hi, comma := strings.Cut(s[1:len(s)-1], ",")
	lo = count(lo)
	switch {
	case !comma:
		return "{" + lo + "}", nil
	case hi == "":
		return "{" + lo + ",}", nil
	}
	hi = count(hi)
	if len(lo) > len(hi) || len(lo) == len(hi) && lo > hi {
		return "", errors.New("min repeat greater than max repeat")
	}
	return "{" + lo + "," + hi + "}", nil
}

// braceRepeat returns the length of the {m,n} repeat at the start of s, or
// 0 when s does not start with one. As in Python, m and n may be empty, so
// that {,} is a repeat, while {} and a { that no } closes after the digits
// are literal text.
func braceRepeat(s string) int {
	if !strings.HasPrefix(s, "{") || strings.HasPrefix(s, "{}") {
		return 0
	}
	j := 1
	for j < len(s) && '0' <= s[j] && s[j] <= '9' {
		j++
	}
	if j < len(s) && s[j] == ',' {
		j++
		for j < len(s) && '0' <= s[j] && s[j] <= '9' {
			j++
		}
	}
	if j < len(s) && s[j] == '}' {
		return j + 1
	}
	return 0
}

// scope is the state of the inline flags that the class translation needs
// inside one group.
type scope struct {
	fold    bool // IgnoreCase
	verbose bool
	uni     bool // Unicode classes: a str pattern outside (?a)
}

// checkCharsetFlags checks the a, u and L letters of one inline flag group,
// on and off being the letters before and after its "-", the way Python's
// re does. str says whether the pattern is a str pattern.
func checkCharsetFlags(on, off string, str bool) error {
	if strings.ContainsAny(off, "auL") {
		return errors.New("bad inline flags: cannot turn off flags 'a', 'u' and 'L'")
	}
	n := 0
	for _, c := range "auL" {
		if strings.ContainsRune(on, c) {
			n++
		}
	}
	switch {
	case n > 1:
		return errors.New("bad inline flags: flags 'a', 'u' and 'L' are incompatible")
	case str && strings.Contains(on, "L"):
		return errors.New("bad inline flags: cannot use 'L' flag with a str pattern")
	case !str && strings.Contains(on, "u"):
		return errors.New("bad inline flags: cannot use 'u' flag with a bytes pattern")
	}
	return nil
}

// classTranslator rewrites the class escapes of a pattern once for each
// engine.
type classTranslator struct {
	src   string
	str   bool
	re2   strings.Builder
	bt    strings.Builder
	re2OK bool
	// uniBoundary says that a \b stands where the classes are Unicode.
	uniBoundary bool
}

// translation is a pattern rewritten for each engine.
type translation struct {
	re2       string
	re2OK     bool // false when RE2 cannot express the pattern
	backtrack string
	// unicodeBoundary says that a \b stands where the classes are Unicode,
	// so RE2's ASCII \b cannot stand for it.
	unicodeBoundary bool
}

func (t *classTranslator) both(s string) {
	t.re2.WriteString(s)
	t.bt.WriteString(s)
}

// translateClasses gives \d, \D, \w, \W, \s, \S, \b and \B the meaning
// Python's re gives them: Unicode where flags has Unicode or a scoped (?u:
// group says so, ASCII elsewhere. str says whether the pattern is a str
// pattern, which decides which scoped a, u and L flags are errors.
//
// The escapes are found by scanning the source rather than the parsed
// tree, because regexp/syntax turns \d and [0-9] into the same node. The
// scanner knows escapes, character classes, comments and the scoped a, u,
// i and x flags, which is all it needs to find the escapes and to tell a class
// member from a range.
//
// Each class escape becomes an explicit class with case folding turned
// off. In a character class that has other members, RE2 gets one class
// holding the union, computed with the case folding in force at that
// point; regexp2 gets one class where nothing folds, otherwise an
// alternation whose branches cannot match the same character or, for a
// negated class, a lookahead, so that it keeps interpreting the other
// members itself. RE2 keeps \b in
// ASCII classes, where its ASCII word boundary is Python's; compileRE2
// sends every other \b and \B to regexp2, where they become lookarounds.
func translateClasses(body string, flags Flags, str, verbose bool) (translation, error) {
	// A class can hold a [ only if the body has two of them. Verbose
	// whitespace can stand between two quantifiers, and a { may start a
	// repeat to rewrite.
	if !verbose && !hasScannedEscape(body) && !strings.ContainsAny(body, "{") && !strings.Contains(body, "(?") && strings.Count(body, "[") < 2 {
		return translation{re2: body, re2OK: true, backtrack: body}, nil
	}
	t := &classTranslator{src: body, str: str, re2OK: true}
	t.re2.Grow(len(body))
	t.bt.Grow(len(body))
	stack := []scope{{fold: flags&IgnoreCase != 0, verbose: verbose, uni: flags&Unicode != 0}}
	src := body
	// Python reads a ? or + right after a quantifier as making it lazy or
	// possessive, and a quantifier after a repeat and a comment or verbose
	// whitespace as an error. Both Go engines drop that text first and see
	// a lazy quantifier in a*(?#c)?, so the scanner tracks whether the
	// last token was a repeat, whether ignored text has followed it, and
	// whether the last token opened a group, after which ? starts the
	// group's syntax.
	var repeat, gap, open bool
	for i := 0; i < len(src); {
		cur := stack[len(stack)-1]
		c := src[i]
		switch {
		case c == '(' && strings.HasPrefix(src[i:], "(?#"),
			c == '#' && cur.verbose, cur.verbose && strings.IndexByte(" \t\n\r\v\f", c) >= 0:
			gap, open = true, false
		default:
			n := braceRepeat(src[i:])
			if c == '*' || c == '+' || c == '?' && !open {
				n = 1
			}
			if n > 0 && repeat && gap {
				return translation{}, errors.New("multiple repeat")
			}
			repeat, gap, open = n > 0, false, c == '('
			if n > 0 {
				text := src[i : i+n]
				if c == '{' {
					var err error
					if text, err = repeatText(text); err != nil {
						return translation{}, err
					}
				}
				t.both(text)
				i += n
				continue
			}
		}
		switch {
		case c == '\\':
			if i+1 == len(src) {
				t.both(src[i:])
				i++
				continue
			}
			if err := foreignEscape(src, i); err != nil {
				return translation{}, err
			}
			switch e := src[i+1]; {
			case e == 'u' || e == 'U':
				text, end, err := codePointEscape(src, i, str)
				if err != nil {
					return translation{}, err
				}
				t.both(text)
				i = end
				continue
			case isShorthand(e):
				c := shorthandExpr([]byte{e}, cur.uni)
				t.re2.WriteString(c.exact())
				t.bt.WriteString(c.backtrackExact())
			case e == 'b' || e == 'B':
				t.re2.WriteString(src[i : i+2])
				t.bt.WriteString(boundary(e, cur.uni))
				t.uniBoundary = t.uniBoundary || e == 'b' && cur.uni
			default:
				t.both(src[i : i+2])
			}
			i += 2
		case c == '[':
			end, err := t.class(i, cur)
			if err != nil {
				return translation{}, err
			}
			i = end
		case c == '(' && strings.HasPrefix(src[i:], "(?#"):
			// Python ignores comments, so neither engine sees them: both
			// would end one at the first ), escaped or not. An empty group
			// keeps the text on either side apart, as in \1(?#c)0, except
			// before a quantifier, which binds to what precedes the
			// comment: a(?#c)* is a*.
			rest := skipIgnored(src[i:], cur.verbose)
			if strings.HasPrefix(rest, "(?#") {
				return translation{}, errors.New("missing ), unterminated comment")
			}
			if rest == "" || strings.IndexByte("*+?{", rest[0]) < 0 {
				t.both("(?:)")
			}
			i = len(src) - len(rest)
		case c == '(':
			if err := checkGlobalFlags(src[i:]); err != nil {
				return translation{}, err
			}
			next, err := scopedFlags(src[i+1:], cur, str)
			if err != nil {
				return translation{}, err
			}
			stack = append(stack, next)
			// Neither engine knows the a, u and L flags; drop them from
			// the group's header, wherever they stand in it.
			if on, off, n, ok := flagGroup(src[i+1:]); ok && strings.ContainsAny(on, "auL") {
				header := "(?" + strings.Map(func(r rune) rune {
					if strings.ContainsRune("auL", r) {
						return -1
					}
					return r
				}, on)
				if off != "" {
					header += "-" + off
				}
				t.both(header + ":")
				i += 1 + n
				open = false
				continue
			}
			t.both("(")
			i++
		case c == ')':
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			t.both(")")
			i++
		case c == '#' && cur.verbose:
			end := len(src)
			if j := strings.IndexByte(src[i:], '\n'); j >= 0 {
				end = i + j + 1
			}
			t.both(src[i:end])
			i = end
		default:
			t.re2.WriteByte(c)
			t.bt.WriteByte(c)
			i++
		}
	}
	return translation{re2: t.re2.String(), re2OK: t.re2OK, backtrack: t.bt.String(), unicodeBoundary: t.uniBoundary}, nil
}

// skipIgnored returns s without the text Python ignores at its start: (?#
// comments and, when verbose is set, whitespace and # comments. An
// unterminated (?# comment is left in place.
func skipIgnored(s string, verbose bool) string {
	for {
		switch {
		case strings.HasPrefix(s, "(?#"):
			end, ok := commentEnd(s, 3)
			if !ok {
				return s
			}
			s = s[end:]
		case verbose && s != "" && strings.IndexByte(" \t\n\r\v\f", s[0]) >= 0:
			s = s[1:]
		case verbose && strings.HasPrefix(s, "#"):
			_, after, found := strings.Cut(s, "\n")
			if !found {
				return ""
			}
			s = after
		default:
			return s
		}
	}
}

// commentEnd returns the index after the ) that closes a (?# comment whose
// text starts at i, and false when no ) closes it. Like Python, it skips
// the character after a backslash.
func commentEnd(src string, i int) (int, bool) {
	for i < len(src) {
		switch src[i] {
		case '\\':
			i += 2
		case ')':
			return i + 1, true
		default:
			i++
		}
	}
	return len(src), false
}

// checkGlobalFlags rejects a flag group without a colon, such as (?i) or
// (?-i), at the start of rest. leadingFlags has taken those at the start
// of the pattern; Python 3.11 and later reject global flags anywhere else
// and have no form that turns a flag off globally, while RE2 and regexp2
// accept both and apply them to the rest of the pattern.
func checkGlobalFlags(rest string) error {
	body, ok := strings.CutPrefix(rest, "(?")
	if !ok {
		return nil
	}
	j := 0
	for j < len(body) && (body[j] == '-' || 'a' <= body[j] && body[j] <= 'z' || 'A' <= body[j] && body[j] <= 'Z') {
		j++
	}
	if j > 0 && j < len(body) && body[j] == ')' {
		return fmt.Errorf("global flags %s not at the start of the expression", rest[:j+3])
	}
	return nil
}

// scopedFlags returns the scope inside a group whose text after "(" is
// rest: cur changed by the flags of a (?flags-flags:...) group, or cur
// itself for any other group. It rejects the flags Python rejects; str
// says whether the pattern is a str pattern.
func scopedFlags(rest string, cur scope, str bool) (scope, error) {
	on, off, n, ok := flagGroup(rest)
	if !ok {
		return cur, nil
	}
	_, after, dash := strings.Cut(rest[1:n-1], "-")
	switch {
	case dash && (after == "" || after[0] == '-'):
		return cur, errors.New("missing flag")
	case strings.Contains(after, "-"):
		return cur, errors.New("missing : after the inline flags")
	case off != "" && strings.ContainsAny(on, off):
		return cur, errors.New("bad inline flags: flag turned on and off")
	}
	if err := checkCharsetFlags(on, off, str); err != nil {
		return cur, err
	}
	next := cur
	switch {
	case strings.Contains(on, "a"):
		next.uni = false
	case strings.Contains(on, "u"):
		next.uni = true
	}
	if strings.Contains(on, "i") {
		next.fold = true
	}
	if strings.Contains(off, "i") {
		next.fold = false
	}
	if strings.Contains(on, "x") {
		next.verbose = true
	}
	if strings.Contains(off, "x") {
		next.verbose = false
	}
	return next, nil
}

// flagGroup reports whether rest, the text after a "(", opens a
// (?flags-flags:...) group, and returns the letters before and after the
// first "-" and the length of the header up to and including the ":".
// The header may hold dashes Python rejects; scopedFlags checks them.
func flagGroup(rest string) (on, off string, n int, ok bool) {
	body, found := strings.CutPrefix(rest, "?")
	if !found {
		return "", "", 0, false
	}
	// Read only the flag letters, so that the scan of a pattern stays
	// linear however many groups it opens.
	end := 0
	for end < len(body) && strings.IndexByte("aiLmsux-", body[end]) >= 0 {
		end++
	}
	if end == len(body) || body[end] != ':' {
		return "", "", 0, false
	}
	if end == 0 {
		return "", "", 0, false
	}
	on, off, _ = strings.Cut(body[:end], "-")
	return on, off, end + 2, true
}

// classItem is one member of a character class: a class escape such as \w,
// or a single character, possibly escaped.
type classItem struct {
	text  string
	short byte // the class escape letter, or 0
}

// literal returns the item as text for a rebuilt class, escaping the
// characters that would mean something else at a new position, and [,
// which Python reads as a member while RE2 reads [: as the start of a
// POSIX class and regexp2 reads -[ as the start of a class subtraction.
func (it classItem) literal() string {
	switch it.text {
	case "-", "^", "]", "[":
		return `\` + it.text
	}
	return it.text
}

// readItem reads the class member at src[i:]. It reports false when the
// pattern ends first, and an error for an escape Python rejects.
func (t *classTranslator) readItem(i int) (classItem, int, bool, error) {
	src := t.src
	if i >= len(src) {
		return classItem{}, i, false, nil
	}
	if src[i] != '\\' {
		_, size := utf8.DecodeRuneInString(src[i:])
		return classItem{text: src[i : i+size]}, i + size, true, nil
	}
	if i+1 >= len(src) {
		return classItem{}, i, false, nil
	}
	if err := foreignEscape(src, i); err != nil {
		return classItem{}, i, false, err
	}
	switch e := src[i+1]; {
	case isShorthand(e):
		return classItem{text: src[i : i+2], short: e}, i + 2, true, nil
	case e == 'u' || e == 'U':
		text, end, err := codePointEscape(src, i, t.str)
		return classItem{text: text}, end, err == nil, err
	}
	end := escapeEnd(src, i)
	return classItem{text: src[i:end]}, end, true, nil
}

// escapeEnd returns the index after the escape that starts with the
// backslash at src[i], with i+1 < len(src). foreignEscape has refused \p,
// \P and \x{, and codePointEscape reads \u and \U.
func escapeEnd(src string, i int) int {
	j := i + 2
	digits := func(n int, ok func(byte) bool) int {
		k := j
		for k < len(src) && k-j < n && ok(src[k]) {
			k++
		}
		return k
	}
	braced := func() (int, bool) {
		if j < len(src) && src[j] == '{' {
			if k := strings.IndexByte(src[j:], '}'); k >= 0 {
				return j + k + 1, true
			}
			return len(src), true
		}
		return 0, false
	}
	switch e := src[i+1]; {
	case e == 'x':
		return digits(2, isHex)
	case e == 'N':
		if k, ok := braced(); ok {
			return k
		}
		return j
	case '0' <= e && e <= '7':
		return digits(2, func(c byte) bool { return '0' <= c && c <= '7' })
	case e >= utf8.RuneSelf:
		_, size := utf8.DecodeRuneInString(src[i+1:])
		return i + 1 + size
	}
	return j
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// class translates the character class that starts with the [ at src[i]
// and returns the index after it. It follows the loop of Python's
// sre_parse: a ] right after [ or [^ is a member, and a - between two
// members is a range unless a ] follows it. A range with a class escape at
// either end is an error, as in Python. A class that the pattern does not
// close is copied as it is, for the engines to reject. Every other class is
// rebuilt from its members, so that each [ in it is escaped.
func (t *classTranslator) class(i int, cur scope) (int, error) {
	src := t.src
	j := i + 1
	neg := j < len(src) && src[j] == '^'
	if neg {
		j++
	}
	var (
		rest   strings.Builder
		shorts []byte
	)
	for first := true; ; first = false {
		if j >= len(src) {
			t.both(src[i:])
			return len(src), nil
		}
		if src[j] == ']' && !first {
			j++
			break
		}
		this, k, ok, err := t.readItem(j)
		if err != nil {
			return 0, err
		}
		if !ok {
			t.both(src[i:])
			return len(src), nil
		}
		if k+1 < len(src) && src[k] == '-' && src[k+1] != ']' {
			that, k2, ok, err := t.readItem(k + 1)
			if err != nil {
				return 0, err
			}
			if !ok {
				t.both(src[i:])
				return len(src), nil
			}
			if this.short != 0 || that.short != 0 {
				return 0, fmt.Errorf("bad character range %s-%s", this.text, that.text)
			}
			rest.WriteString(this.literal() + "-" + that.literal())
			j = k2
			continue
		}
		if this.short != 0 {
			shorts = append(shorts, this.short)
		} else {
			rest.WriteString(this.literal())
		}
		j = k
	}
	if len(shorts) == 0 {
		if neg {
			t.both("[^" + rest.String() + "]")
		} else {
			t.both("[" + rest.String() + "]")
		}
		return j, nil
	}

	// A repeated escape adds nothing to the class. Keeping one of each, at
	// most six, keeps the emitted class the same size however many repeats
	// the pattern holds, and sends a single escape to the cached form.
	slices.Sort(shorts)
	shorts = slices.Compact(shorts)
	sh := shorthandExpr(shorts, cur.uni)
	if rest.Len() == 0 {
		if neg {
			sh = sh.negate()
		}
		t.re2.WriteString(sh.exact())
		t.bt.WriteString(sh.backtrackExact())
		return j, nil
	}

	others := rest.String()
	switch {
	case neg:
		t.bt.WriteString("(?:(?![" + others + "])" + sh.negate().backtrackExact() + ")")
	case !cur.fold && strings.HasPrefix(sh.text, "[") && !strings.HasPrefix(sh.text, "[^"):
		// Nothing folds, so one bracket expression holds both. The
		// property body goes first: a member such as \x4 could otherwise
		// run into the digits that start it.
		t.bt.WriteString(sh.text[:len(sh.text)-1] + others + "]")
	default:
		// The members fold and the escape must not, so they are two
		// branches. The second refuses what the first matches: branches
		// that overlap, under a quantifier, make regexp2 try every way of
		// splitting a run between them before it gives up.
		t.bt.WriteString("(?:" + sh.backtrackExact() + "|(?!" + sh.exact() + ")[" + others + "])")
	}
	if !t.re2OK {
		return j, nil
	}
	members, ok := re2ClassSet("["+others+"]", cur.fold)
	if !ok {
		t.re2OK = false
		return j, nil
	}
	set := members.union(sh.set)
	if neg {
		set = set.negate()
	}
	t.re2.WriteString(classExpr{set: set}.exact())
	return j, nil
}

// re2ClassSet returns the runes the class src matches on RE2, with case
// folding when fold is set. It reports false when RE2 rejects src.
func re2ClassSet(src string, fold bool) (runeSet, bool) {
	flags := syntax.Perl
	if fold {
		flags |= syntax.FoldCase
	}
	re, err := syntax.Parse(src, flags)
	if err != nil {
		return nil, false
	}
	switch re.Op {
	case syntax.OpCharClass:
		return runeSet(slices.Clone(re.Rune)).normalize(), true
	case syntax.OpLiteral:
		if len(re.Rune) != 1 {
			return nil, false
		}
		r := re.Rune[0]
		s := runeSet{r, r}
		if re.Flags&syntax.FoldCase != 0 {
			for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
				s = append(s, f, f)
			}
		}
		return s.normalize(), true
	case syntax.OpAnyChar:
		return runeSet{0, unicode.MaxRune}, true
	case syntax.OpAnyCharNotNL:
		return runeSet{0, '\n' - 1, '\n' + 1, unicode.MaxRune}, true
	case syntax.OpNoMatch:
		return runeSet{}, true
	}
	return nil, false
}
