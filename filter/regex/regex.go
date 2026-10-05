// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package regex compiles the regular expressions used by flow filters.
//
// mitmproxy evaluates filter patterns with Python's re module. Most patterns
// people write are valid RE2, so Compile tries the standard regexp package
// first: it runs in linear time and cannot be made to backtrack. Patterns
// that RE2 rejects, typically because they use lookaround or
// backreferences, fall back to github.com/dlclark/regexp2, a backtracking
// engine with Perl/.NET syntax. A backtracking engine can take exponential
// time on hostile input, so every regexp2 match is bounded by MatchTimeout;
// a match that runs out of time counts as no match and is reported to the
// Logger.
//
// Python syntax that neither engine shares is translated before
// compilation:
//
//   - Global inline flag groups at the start of the pattern, such as (?s)
//     or (?im), become Flags. Python records them in the compiled pattern's
//     flags, and the filter layer prints those flags, so Matcher.Flags
//     reports them as well. x (verbose) is honoured by compiling with
//     regexp2.
//   - The Python-only flags a, u and L choose what \d, \w, \s and \b
//     match, globally or in a scoped group such as (?a:...). a makes them
//     ASCII and, globally, removes Unicode from the reported flags; u keeps
//     a str pattern's Unicode classes. They are rejected where Python
//     rejects them: L in a str pattern, u in a bytes pattern, two of them
//     in one group, a with u or L across global groups, and any of them
//     after "-". L in a bytes pattern makes Python follow the C library's
//     locale; here the classes stay ASCII.
//   - \d, \D, \w, \W, \s and \S, also inside character classes, become
//     explicit classes that match what Python matches: Unicode categories
//     for a str pattern (Unicode), ASCII for a bytes pattern, and never
//     folded for case. Neither Go engine agrees with Python on its own: RE2
//     is ASCII-only, and regexp2 uses the .NET definitions. They are found
//     by scanning the pattern source, not by rewriting the parsed tree as
//     for $, because regexp/syntax parses \d and [0-9] into the same node.
//   - \b keeps RE2's ASCII meaning in a bytes pattern. In a str pattern, and
//     \B in any pattern, the pattern goes to regexp2, where they become
//     lookarounds on Python's word characters. Python's \B does not match
//     in an empty input.
//   - \Z, which Python defines as the absolute end of the input, becomes
//     \z. RE2 rejects \Z and regexp2 gives it the .NET meaning "end or
//     before a final newline".
//   - Without Multiline, Python's $ matches at the end of the input and
//     also before a newline that ends it, while RE2's $ matches only at the
//     end. A $ that nothing can follow, such as the one in "\.js$" or
//     "(a$|b$)", becomes "\n?\z" for RE2, which is the same thing for a
//     search. A $ anywhere else, such as in "a$\n" or "(a$)+", sends the
//     pattern to regexp2, whose $ already has Python's meaning.
//   - A repeat without a minimum, {,n} or {,}, repeats from 0, as in
//     Python; both engines would read it as text. A count with leading
//     zeros, which RE2 would read as text, loses them.
//   - \uXXXX and \UXXXXXXXX in a str pattern become \x{...}: RE2 knows
//     neither and regexp2 lacks \U. A bytes pattern rejects both, as Python
//     does.
//   - A possessive repeat such as a*+, [ab]++ or (x|y){2,}+ becomes the
//     atomic group (?>a*), which is how CPython defines it, and the
//     pattern goes to regexp2: RE2 has neither form, and regexp2 has
//     atomic groups but reads *+ as two repeats.
//   - Python's named group (?P<name>...), named backreference (?P=name)
//     and numbered backreference \N become regexp2's (?<name>...),
//     \k<name> and \k<N>: regexp2 rejects the first two and reads \10 as
//     an octal escape where Python reads group 10. A conditional without
//     a no branch gets an empty one, which regexp2 needs to match as
//     Python does.
//
// A known difference that is not translated: Python's bytes patterns treat
// input as Latin-1 bytes and fold case for ASCII only, while both Go engines
// decode UTF-8 and fold case for all of Unicode. The Unicode classes follow
// the Unicode version of Go's unicode package rather than Python's.
package regex

import (
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
)

// MatchTimeout bounds a single match on the regexp2 fallback engine.
const MatchTimeout = 100 * time.Millisecond

// Flags are the Python re flags a filter pattern is compiled with.
type Flags uint8

const (
	// IgnoreCase makes the pattern match letters regardless of case (re.IGNORECASE).
	IgnoreCase Flags = 1 << iota
	// Multiline makes ^ and $ match at line boundaries (re.MULTILINE).
	Multiline
	// DotAll makes . match a newline as well (re.DOTALL).
	DotAll
	// Unicode gives \d, \w, \s and \b their meaning in a Python str
	// pattern (re.UNICODE), which Python also reports in the flags of a
	// str pattern. Without it they have their meaning in a bytes pattern,
	// which is ASCII-only.
	Unicode
)

// String returns the flags as Python's regex_str spells them: a subset of
// "ims" in that order. Unicode is not spelled, as in regex_str.
func (f Flags) String() string {
	var b strings.Builder
	if f&IgnoreCase != 0 {
		b.WriteByte('i')
	}
	if f&Multiline != 0 {
		b.WriteByte('m')
	}
	if f&DotAll != 0 {
		b.WriteByte('s')
	}
	return b.String()
}

// Matcher reports whether a compiled filter pattern occurs in its input.
//
// Match and MatchString search for the pattern anywhere in the input, like
// Python's re.search. A Matcher is safe for concurrent use.
type Matcher interface {
	// Match reports whether the pattern occurs in b.
	Match(b []byte) bool
	// MatchString reports whether the pattern occurs in s.
	MatchString(s string) bool
	// Pattern returns the pattern as it was passed to Compile.
	Pattern() string
	// Flags returns the flags passed to Compile combined with the global
	// inline flags at the start of the pattern, as Python's
	// re.Pattern.flags would report them.
	Flags() Flags
}

// Logger receives the regexp2 matches that were abandoned because they ran
// longer than MatchTimeout. err never holds the whole subject, which can be
// a whole message body: it states the time limit, the subject's length and
// at most its first subjectPrefixLen bytes, quoted.
type Logger func(pattern string, err error)

// subjectPrefixLen bounds how much of the subject an abandoned match
// reports: enough to tell which message it was, little enough to keep the
// log line short and the message body out of the log.
const subjectPrefixLen = 64

var logger atomic.Pointer[Logger]

func init() {
	SetLogger(warnTimeout)
}

// warnTimeout is the default Logger: a warning through log/slog.
func warnTimeout(pattern string, err error) {
	slog.Warn("filter regex match abandoned", "pattern", pattern, "error", err)
}

// SetLogger replaces the function that receives abandoned matches. A nil
// Logger discards them. The default logs a warning through log/slog.
func SetLogger(l Logger) {
	if l == nil {
		logger.Store(nil)
		return
	}
	logger.Store(&l)
}

func logTimeout(pattern string, err error) {
	if l := logger.Load(); l != nil {
		(*l)(pattern, err)
	}
}

// Compile compiles a Python-syntax pattern with the given flags.
//
// It returns an error only when neither RE2 nor regexp2 accepts the
// translated pattern.
func Compile(pattern string, flags Flags) (Matcher, error) {
	str := flags&Unicode != 0
	body, eff, verbose, err := leadingFlags(pattern, flags)
	if err != nil {
		return nil, fmt.Errorf("regex: cannot compile %q: %w", pattern, err)
	}
	tr, err := translateClasses(translateEscapes(body), eff, str, verbose)
	if err != nil {
		return nil, fmt.Errorf("regex: cannot compile %q: %w", pattern, err)
	}
	body = tr.backtrack

	if !verbose && tr.re2OK {
		if re := compileRE2(re2Prefix(eff)+tr.re2, tr.unicodeBoundary); re != nil {
			return &re2Matcher{re: re, pattern: pattern, flags: eff}, nil
		}
	}

	opts := regexp2.None
	if eff&IgnoreCase != 0 {
		opts |= regexp2.IgnoreCase
	}
	if eff&Multiline != 0 {
		opts |= regexp2.Multiline
	}
	if eff&DotAll != 0 {
		opts |= regexp2.Singleline
	}
	if verbose {
		opts |= regexp2.IgnorePatternWhitespace
	}
	re, err := regexp2.Compile(body, opts)
	if err != nil {
		return nil, fmt.Errorf("regex: cannot compile %q: %w", pattern, err)
	}
	re.MatchTimeout = MatchTimeout
	return &backtrackMatcher{re: re, pattern: pattern, flags: eff, options: opts}, nil
}

// compileRE2 compiles src with the standard regexp package, giving $ its
// Python meaning. It returns nil when RE2 rejects src, when a $ is not in
// tail position, or when src has a word boundary RE2 cannot give Python's
// meaning, so that the caller falls back to regexp2. uni says whether a \b
// in src stands where the classes are Unicode.
func compileRE2(src string, uni bool) *regexp.Regexp {
	tree, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return nil
	}
	if foreignBoundary(tree, uni) {
		return nil
	}
	found, tail := pythonDollars(tree, true)
	if !found {
		// Compile the source as written rather than a re-rendered tree.
		re, err := regexp.Compile(src)
		if err != nil {
			return nil
		}
		return re
	}
	if !tail {
		return nil
	}
	rewriteDollars(tree)
	re, err := regexp.Compile(tree.String())
	if err != nil {
		return nil
	}
	return re
}

// foreignBoundary reports whether re has a \B, or a \b when uni is set.
// RE2's \b is an ASCII word boundary, which is Python's \b for a bytes
// pattern only, and RE2's \B matches in an empty input, where Python's does
// not.
func foreignBoundary(re *syntax.Regexp, uni bool) bool {
	switch re.Op {
	case syntax.OpNoWordBoundary:
		return true
	case syntax.OpWordBoundary:
		return uni
	}
	return slices.ContainsFunc(re.Sub, func(sub *syntax.Regexp) bool { return foreignBoundary(sub, uni) })
}

// isPythonDollar reports whether re is a $ outside Multiline, which RE2
// parses as end of text.
func isPythonDollar(re *syntax.Regexp) bool {
	return re.Op == syntax.OpEndText && re.Flags&syntax.WasDollar != 0
}

// pythonDollars reports whether re contains a $ outside Multiline and
// whether every such $ is in tail position: no part of the pattern can
// match after it. tail says whether re itself is in tail position.
func pythonDollars(re *syntax.Regexp, tail bool) (found, allTail bool) {
	if isPythonDollar(re) {
		return true, tail
	}
	allTail = true
	for i, sub := range re.Sub {
		subTail := false
		switch re.Op {
		case syntax.OpConcat:
			subTail = tail && i == len(re.Sub)-1
		case syntax.OpAlternate, syntax.OpCapture:
			subTail = tail
		}
		f, t := pythonDollars(sub, subTail)
		found = found || f
		allTail = allTail && t
	}
	return found, allTail
}

// rewriteDollars replaces every $ outside Multiline with "\n?\z": an
// optional final newline, then the end of the input.
func rewriteDollars(re *syntax.Regexp) {
	if isPythonDollar(re) {
		*re = syntax.Regexp{
			Op: syntax.OpConcat,
			Sub: []*syntax.Regexp{
				{Op: syntax.OpQuest, Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'\n'}}}},
				{Op: syntax.OpEndText},
			},
		}
		return
	}
	for _, sub := range re.Sub {
		rewriteDollars(sub)
	}
}

func re2Prefix(f Flags) string {
	s := f.String()
	if s == "" {
		return ""
	}
	return "(?" + s + ")"
}

// leadingFlags strips the global inline flag groups, such as (?i) or (?sx),
// from the start of pattern, where Python only accepts them, and returns
// flags combined with them. Like Python it skips comments before and
// between them and, once a group has turned on verbose, whitespace. (?a)
// turns Unicode off, as it makes a str pattern's classes ASCII. The a, u
// and L letters are checked the way Python checks them, also across
// groups.
func leadingFlags(pattern string, flags Flags) (body string, eff Flags, verbose bool, err error) {
	body, eff = pattern, flags
	str := flags&Unicode != 0
	var ascii, uni, locale bool
	for {
		body = skipIgnored(body, verbose)
		rest, ok := strings.CutPrefix(body, "(?")
		if !ok {
			break
		}
		end := strings.IndexByte(rest, ')')
		if end <= 0 || strings.Trim(rest[:end], "aiLmsux") != "" {
			break
		}
		if err := checkCharsetFlags(rest[:end], "", str); err != nil {
			return "", 0, false, err
		}
		for _, c := range rest[:end] {
			switch c {
			case 'i':
				eff |= IgnoreCase
			case 'm':
				eff |= Multiline
			case 's':
				eff |= DotAll
			case 'x':
				verbose = true
			case 'a':
				ascii = true
			case 'u':
				uni = true
			case 'L':
				locale = true
			}
		}
		body = rest[end+1:]
	}
	switch {
	case ascii && uni:
		return "", 0, false, errors.New("ASCII and UNICODE flags are incompatible")
	case ascii && locale:
		return "", 0, false, errors.New("ASCII and LOCALE flags are incompatible")
	case ascii:
		eff &^= Unicode
	}
	return body, eff, verbose, nil
}

// translateEscapes rewrites the escapes whose Python meaning differs from
// both Go engines.
func translateEscapes(pattern string) string {
	if !strings.Contains(pattern, `\Z`) {
		return pattern
	}
	var b strings.Builder
	b.Grow(len(pattern))
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c != '\\' || i+1 == len(pattern) {
			b.WriteByte(c)
			continue
		}
		i++
		if pattern[i] == 'Z' {
			b.WriteString(`\z`)
			continue
		}
		b.WriteByte('\\')
		b.WriteByte(pattern[i])
	}
	return b.String()
}

type re2Matcher struct {
	re      *regexp.Regexp
	pattern string
	flags   Flags
}

// Match reports whether the byte slice matches the compiled RE2 expression.
func (m *re2Matcher) Match(b []byte) bool { return m.re.Match(b) }

// MatchString reports whether the string matches the compiled RE2 expression.
func (m *re2Matcher) MatchString(s string) bool { return m.re.MatchString(s) }

// Pattern returns the original regular expression text.
func (m *re2Matcher) Pattern() string { return m.pattern }

// Flags returns the flags used to compile the expression.
func (m *re2Matcher) Flags() Flags { return m.flags }

type backtrackMatcher struct {
	re      *regexp2.Regexp
	pattern string
	flags   Flags
	options regexp2.RegexOptions
}

// MatchStringReport searches s and reports whether the fallback engine abandoned
// the match at MatchTimeout. Unlike Matcher.MatchString, it never calls Logger.
// An RE2 match is never abandoned.
func MatchStringReport(m Matcher, s string) (matched, abandoned bool) {
	return MatchStringReportTimeout(m, s, MatchTimeout)
}

// MatchStringReportTimeout is MatchStringReport with a caller-selected fallback
// limit. It never changes m's timeout, so concurrent calls remain independent.
// The limit is ignored for RE2 and other Matcher implementations, which report
// their MatchString result with abandoned false.
func MatchStringReportTimeout(m Matcher, s string, limit time.Duration) (matched, abandoned bool) {
	bt, ok := m.(*backtrackMatcher)
	if !ok {
		return m.MatchString(s), false
	}
	re := bt.re
	if limit != MatchTimeout {
		// Regexp contains a mutex and cannot be copied. Recompile its already
		// validated source for custom limits rather than mutate shared state.
		re = regexp2.MustCompile(bt.re.String(), bt.options)
		re.MatchTimeout = limit
	}
	matched, err := re.MatchString(s)
	return matched && err == nil, err != nil
}

// Match reports whether the bytes match, treating a backtracking timeout as no match.
func (m *backtrackMatcher) Match(b []byte) bool { return m.MatchString(string(b)) }

// MatchString reports whether the string matches, logging backtracking failures as no match.
func (m *backtrackMatcher) MatchString(s string) bool {
	ok, err := m.re.MatchString(s)
	if err != nil {
		// regexp2's error quotes the whole subject; report a bounded,
		// escaped prefix instead.
		logTimeout(m.pattern, timeoutError(s))
		return false
	}
	return ok
}

// timeoutError describes a match on s that ran into MatchTimeout, with at
// most the first subjectPrefixLen bytes of s, cut before a character that
// would not fit.
func timeoutError(s string) error {
	prefix := s
	if len(s) > subjectPrefixLen {
		n := subjectPrefixLen
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		prefix = s[:n]
	}
	return fmt.Errorf("match abandoned after %v on a %d-byte subject starting %q", MatchTimeout, len(s), prefix)
}

// Pattern returns the original regular expression text.
func (m *backtrackMatcher) Pattern() string { return m.pattern }

// Flags returns the flags used to compile the expression.
func (m *backtrackMatcher) Flags() Flags { return m.flags }

// IsBacktracking reports whether m runs on the regexp2 fallback engine.
func IsBacktracking(m Matcher) bool {
	_, ok := m.(*backtrackMatcher)
	return ok
}
