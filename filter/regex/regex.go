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
//     reports them as well. The Python-only flags a, u and L, which only
//     change what \w, \b and similar classes match, are dropped; x (verbose)
//     is honoured by compiling with regexp2.
//   - \Z, which Python defines as the absolute end of the input, becomes
//     \z. RE2 rejects \Z and regexp2 gives it the .NET meaning "end or
//     before a final newline".
//   - Without Multiline, Python's $ matches at the end of the input and
//     also before a newline that ends it, while RE2's $ matches only at the
//     end. A $ that nothing can follow, such as the one in "\.js$" or
//     "(a$|b$)", becomes "\n?\z" for RE2, which is the same thing for a
//     search. A $ anywhere else, such as in "a$\n" or "(a$)+", sends the
//     pattern to regexp2, whose $ already has Python's meaning.
//
// A known difference that is not translated: Python's bytes patterns treat
// input as Latin-1 bytes and fold case for ASCII only, while both Go engines
// decode UTF-8 and fold case for all of Unicode.
package regex

import (
	"fmt"
	"log/slog"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync/atomic"
	"time"

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
)

// String returns the flags as Python's regex_str spells them: a subset of
// "ims" in that order.
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
// longer than MatchTimeout.
type Logger func(pattern string, err error)

var logger atomic.Pointer[Logger]

func init() {
	SetLogger(func(pattern string, err error) {
		slog.Warn("filter regex match abandoned", "pattern", pattern, "error", err)
	})
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
	body, inline, verbose := leadingFlags(pattern)
	if err := checkFlagGroups(body); err != nil {
		return nil, fmt.Errorf("regex: cannot compile %q: %w", pattern, err)
	}
	body = translateEscapes(body)
	eff := flags | inline

	if !verbose {
		if re := compileRE2(re2Prefix(eff) + body); re != nil {
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
	return &backtrackMatcher{re: re, pattern: pattern, flags: eff}, nil
}

// compileRE2 compiles src with the standard regexp package, giving $ its
// Python meaning. It returns nil when RE2 rejects src or when a $ is not in
// tail position, so that the caller falls back to regexp2.
func compileRE2(src string) *regexp.Regexp {
	tree, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
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
	if f == 0 {
		return ""
	}
	return "(?" + f.String() + ")"
}

// leadingFlags strips the global inline flag groups, such as (?i) or (?sx),
// from the start of pattern. Python only accepts global flags there.
func leadingFlags(pattern string) (body string, flags Flags, verbose bool) {
	body = pattern
	for {
		rest, ok := strings.CutPrefix(body, "(?")
		if !ok {
			return body, flags, verbose
		}
		end := strings.IndexByte(rest, ')')
		if end <= 0 || strings.Trim(rest[:end], "aiLmsux") != "" {
			return body, flags, verbose
		}
		for _, c := range rest[:end] {
			switch c {
			case 'i':
				flags |= IgnoreCase
			case 'm':
				flags |= Multiline
			case 's':
				flags |= DotAll
			case 'x':
				verbose = true
			}
		}
		body = rest[end+1:]
	}
}

// checkFlagGroups rejects a flag group without a colon, such as (?i) or
// (?-i), anywhere but the start of the pattern. Python 3.11 and later reject
// global flags that are not at the start and has no form that turns a flag
// off globally, while RE2 and regexp2 accept both and apply them to the
// rest of the pattern.
func checkFlagGroups(body string) error {
	inClass := false
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c == '\\':
			i++
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
			// A ] right after [ or [^ is a literal member of the class.
			if i+1 < len(body) && body[i+1] == '^' {
				i++
			}
			if i+1 < len(body) && body[i+1] == ']' {
				i++
			}
		case c == '(' && strings.HasPrefix(body[i:], "(?"):
			j := i + 2
			for j < len(body) && (body[j] == '-' || 'a' <= body[j] && body[j] <= 'z' || 'A' <= body[j] && body[j] <= 'Z') {
				j++
			}
			if j > i+2 && j < len(body) && body[j] == ')' {
				return fmt.Errorf("global flags %s not at the start of the expression", body[i:j+1])
			}
		}
	}
	return nil
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

func (m *re2Matcher) Match(b []byte) bool       { return m.re.Match(b) }
func (m *re2Matcher) MatchString(s string) bool { return m.re.MatchString(s) }
func (m *re2Matcher) Pattern() string           { return m.pattern }
func (m *re2Matcher) Flags() Flags              { return m.flags }

type backtrackMatcher struct {
	re      *regexp2.Regexp
	pattern string
	flags   Flags
}

func (m *backtrackMatcher) Match(b []byte) bool { return m.MatchString(string(b)) }

func (m *backtrackMatcher) MatchString(s string) bool {
	ok, err := m.re.MatchString(s)
	if err != nil {
		logTimeout(m.pattern, err)
		return false
	}
	return ok
}

func (m *backtrackMatcher) Pattern() string { return m.pattern }
func (m *backtrackMatcher) Flags() Flags    { return m.flags }

// IsBacktracking reports whether m runs on the regexp2 fallback engine.
func IsBacktracking(m Matcher) bool {
	_, ok := m.(*backtrackMatcher)
	return ok
}
