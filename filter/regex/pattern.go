// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package regex

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
)

const (
	maxPatternBytes = 1 << 20
	maxSubBytes     = 256 << 20
	maxSubMatches   = 1 << 20
	maxMatchBytes   = 1 << 20
)

// Pattern is a concurrent-safe Python expression with captures and substitution.
// Unlike Compile's boolean matcher, it preserves match spans at a final newline
// and Python's group numbering. Without Unicode, pattern and subject bytes are
// interpreted as Latin-1 rather than UTF-8.
//
// Patterns are limited to 1 MiB; subjects, templates and substituted outputs are
// limited to 256 MiB. Substitution permits at most 1,048,576 matches. RE2
// substitutions retain only the current match when the pattern has no
// anchors or boundaries; context-sensitive patterns retain a whole-subject
// table bounded to 1 MiB of estimated index storage and reject excess matches.
// Every fallback search is bounded by MatchTimeout.
// Search and Sub report abandoned searches as errors without calling Logger.
// Match and MatchString instead log abandoned searches and return false.
type Pattern struct {
	re           *regexp.Regexp
	contextual   bool
	bt, nonempty *regexp2.Regexp
	pattern      string
	flags        Flags
	str          bool
	groups       int
	names        map[string]int
	options      regexp2.RegexOptions
}

var _ Matcher = (*Pattern)(nil)

// Match holds captures in Python numbering, with the complete match at index 0.
// Spans are half-open byte offsets into the original input; an unmatched group
// has span [-1, -1] and an empty string. Empty participating groups have a
// zero-length span, so callers can distinguish them from unmatched groups.
type Match struct {
	Groups []string
	Spans  [][2]int
}

// CompilePattern compiles a Python expression for capture and substitution.
// Unicode selects a string pattern; otherwise each byte is a Latin-1 character.
// RE2 is preferred, with the bounded fallback used for lookaround, Python's
// non-multiline dollar, and patterns that can match empty text. The latter need
// Python's retry of a nonempty alternative at the same position after an empty
// match, which RE2's non-overlapping iterator cannot express.
func CompilePattern(pattern string, flags Flags) (*Pattern, error) {
	if len(pattern) > maxPatternBytes {
		return nil, errors.New("regex: pattern exceeds 1 MiB")
	}
	str := flags&Unicode != 0
	src := pattern
	if !str {
		src = latin1(src)
	} else if !utf8.ValidString(src) {
		return nil, errors.New("regex: string pattern is not valid UTF-8")
	}
	body, eff, verbose, err := leadingFlags(src, flags)
	if err != nil {
		return nil, fmt.Errorf("regex: cannot compile %q: %w", pattern, err)
	}
	tr, _, err := scanClassesCaptures(translateEscapes(body), eff, str, verbose, true)
	if err != nil {
		return nil, fmt.Errorf("regex: cannot compile %q: %w", pattern, err)
	}
	p := &Pattern{pattern: pattern, flags: eff, str: str, groups: tr.groups, names: tr.names}
	if !verbose && tr.re2OK {
		src = re2Prefix(eff) + tr.re2
		if tree, err := syntax.Parse(src, syntax.Perl); err == nil && !foreignBoundary(tree, tr.unicodeBoundary) && !emptyPattern(tree) {
			if dollar, _ := pythonDollars(tree, true); !dollar {
				if p.re, err = regexp.Compile(src); err == nil {
					p.contextual = contextualPattern(tree)
					return p, nil
				}
			}
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
	p.options = opts
	p.bt, err = regexp2.Compile(tr.backtrack, opts)
	if err != nil {
		return nil, fmt.Errorf("regex: cannot compile %q: %w", pattern, err)
	}
	p.bt.MatchTimeout = MatchTimeout
	// The engine's \G is the current search start. Appending this assertion
	// rejects an empty match there without rejecting a consuming alternative.
	retry := tr.backtrack
	if verbose {
		retry += "\n"
	}
	p.nonempty, err = regexp2.Compile("\\G(?:"+retry+")(?!\\G)", opts)
	if err != nil {
		return nil, fmt.Errorf("regex: cannot compile nonempty retry: %w", err)
	}
	p.nonempty.MatchTimeout = MatchTimeout
	return p, nil
}

// byteFoldLiteral prevents the engine from folding a non-ASCII byte. regexp2
// additionally needs an unconstrained start when its start-character optimiser
// would lowercase that byte despite the local case-sensitive group.
func byteFoldLiteral(t *classTranslator, text string) bool {
	tree, err := syntax.Parse(text, syntax.Perl)
	if err != nil || tree.Op != syntax.OpLiteral || len(tree.Rune) != 1 || tree.Rune[0] < utf8.RuneSelf {
		return false
	}
	r := tree.Rune[0]
	expr := newClassExpr(runeSet{r, r}, "")
	t.re2.WriteString(expr.exact())
	t.bt.WriteString(expr.backtrackExact())
	return true
}

func contextualPattern(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	default:
		return slices.ContainsFunc(re.Sub, contextualPattern)
	}
}

func emptyPattern(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return false
	case syntax.OpLiteral:
		return len(re.Rune) == 0
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			if !emptyPattern(sub) {
				return false
			}
		}
		return true
	case syntax.OpAlternate:
		return slices.ContainsFunc(re.Sub, emptyPattern)
	case syntax.OpCapture, syntax.OpPlus:
		return emptyPattern(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min == 0 || emptyPattern(re.Sub[0])
	default:
		return true
	}
}

func latin1(s string) string {
	ascii := true
	for i := range len(s) {
		ascii = ascii && s[i] < utf8.RuneSelf
	}
	if ascii {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		b.WriteRune(rune(s[i]))
	}
	return b.String()
}

// Pattern returns the original expression text.
func (p *Pattern) Pattern() string { return p.pattern }

// Flags returns effective flags, including global inline flags.
func (p *Pattern) Flags() Flags { return p.flags }

// Match reports whether the pattern occurs in b, logging abandoned searches.
func (p *Pattern) Match(b []byte) bool {
	if len(b) > maxSubBytes {
		logTimeout(p.pattern, errors.New("regex: subject exceeds 256 MiB"))
		return false
	}
	return p.MatchString(string(b))
}

// MatchString reports whether the pattern occurs in s, logging abandoned searches.
func (p *Pattern) MatchString(s string) bool {
	m, err := p.SearchString(s)
	if err != nil {
		logTimeout(p.pattern, err)
	}
	return m != nil && err == nil
}

// Search searches b and returns captures, nil for no match, or a bounded error.
func (p *Pattern) Search(b []byte) (*Match, error) {
	if len(b) > maxSubBytes {
		return nil, errors.New("regex: subject exceeds 256 MiB")
	}
	return p.SearchString(string(b))
}

// SearchString searches s and returns captures with original byte offsets.
// Invalid UTF-8 is rejected in string mode; every byte is valid in bytes mode.
func (p *Pattern) SearchString(s string) (*Match, error) {
	input, err := p.input(s)
	if err != nil {
		return nil, err
	}
	if p.re != nil {
		idx := p.re.FindStringSubmatchIndex(input.text)
		if idx == nil {
			return nil, nil
		}
		return input.re2Match(idx), nil
	}
	m, err := p.bt.FindRunesMatch(input.runes)
	if err != nil {
		return nil, timeoutError(s)
	}
	if m == nil {
		return nil, nil
	}
	return p.backtrackMatch(input, m), nil
}

// Sub replaces up to count matches in subject using a Python replacement template.
// A count of zero replaces all matches; a negative count replaces none.
// It returns no partial result if a search is abandoned or the output exceeds
// 256 MiB. Python escapes, numbered and named references are supported.
func (p *Pattern) Sub(replacement, subject []byte, count int) ([]byte, error) {
	if len(replacement) > maxSubBytes {
		return nil, errors.New("regex: replacement exceeds 256 MiB")
	}
	if len(subject) > maxSubBytes {
		return nil, errors.New("regex: subject exceeds 256 MiB")
	}
	s, err := p.SubString(string(replacement), string(subject), count)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// SubString is Sub for strings, preserving unmatched text byte-for-byte.
func (p *Pattern) SubString(replacement, subject string, count int) (string, error) {
	parts, err := p.template(replacement)
	if err != nil {
		return "", err
	}
	input, err := p.input(subject)
	if err != nil {
		return "", err
	}
	if count < 0 {
		return subject, nil
	}
	var output strings.Builder
	last := 0
	apply := func(m *Match) error {
		if err := appendBounded(&output, subject[last:m.Spans[0][0]]); err != nil {
			return err
		}
		for _, part := range parts {
			text := part.text
			if part.group >= 0 {
				text = m.Groups[part.group]
			}
			if err := appendBounded(&output, text); err != nil {
				return err
			}
		}
		last = m.Spans[0][1]
		return nil
	}
	if p.re != nil {
		// Account for slice headers, capture indices and growth headroom.
		bytesPerMatch := 64 + 32*(p.re.NumSubexp()+1)
		tableLimit := maxMatchBytes / bytesPerMatch
		if tableLimit == 0 {
			return "", errors.New("regex: capture table exceeds working-memory budget")
		}
		limit := maxSubMatches
		if count > 0 {
			limit = min(count, limit)
		}
		m := &Match{Groups: make([]string, p.groups+1), Spans: make([][2]int, p.groups+1)}
		position, replaced := 0, 0
		for position <= len(input.text) {
			n := 1
			if p.contextual {
				// One extra match detects overflow without an unbounded table.
				n = min(tableLimit, limit) + 1
			}
			var indices [][]int
			if p.contextual {
				indices = p.re.FindAllStringSubmatchIndex(input.text, n)
			} else if idx := p.re.FindStringSubmatchIndex(input.text[position:]); idx != nil {
				indices = [][]int{idx}
			}
			if p.contextual && len(indices) > min(tableLimit, limit) {
				// A caller's smaller count is not a budget violation.
				if count > 0 && count <= min(tableLimit, maxSubMatches) {
					indices = indices[:count]
				} else {
					return "", errors.New("regex: too many matches")
				}
			}
			end := position
			for _, idx := range indices {
				if replaced == limit {
					return "", errors.New("regex: too many matches")
				}
				end = position + idx[1]
				for i := range m.Groups {
					start, finish := idx[2*i], idx[2*i+1]
					m.Groups[i] = ""
					if start >= 0 {
						start, finish = start+position, finish+position
						if input.encodedOffsets != nil {
							start, finish = input.encodedOffsets[start], input.encodedOffsets[finish]
						}
						m.Groups[i] = subject[start:finish]
					}
					m.Spans[i] = [2]int{start, finish}
				}
				if err := apply(m); err != nil {
					return "", err
				}
				replaced++
				if count > 0 && replaced == count {
					break
				}
			}
			if p.contextual || len(indices) < n || count > 0 && replaced == count {
				break
			}
			position = end
		}
	} else {
		position, replaced, retry := 0, 0, false
		for position <= len(input.runes) && (count == 0 || replaced < count) {
			re := p.bt
			if retry {
				re = p.nonempty
			}
			m, err := re.FindRunesMatchStartingAt(input.runes, position)
			if err != nil {
				return "", timeoutError(subject)
			}
			if retry && (m == nil || m.Index != position) {
				position++
				retry = false
				continue
			}
			if m == nil {
				break
			}
			if replaced == maxSubMatches {
				return "", errors.New("regex: too many matches")
			}
			if err := apply(p.backtrackMatch(input, m)); err != nil {
				return "", err
			}
			position, retry = m.Index+m.Length, m.Length == 0
			replaced++
		}
	}
	if err := appendBounded(&output, subject[last:]); err != nil {
		return "", err
	}
	return output.String(), nil
}

func appendBounded(b *strings.Builder, s string) error {
	if len(s) > maxSubBytes-b.Len() {
		return errors.New("regex: substituted output exceeds 256 MiB")
	}
	b.WriteString(s)
	return nil
}

type patternInput struct {
	raw, text               string
	runes                   []rune
	offsets, encodedOffsets []int
}

func (p *Pattern) input(s string) (patternInput, error) {
	if len(s) > maxSubBytes {
		return patternInput{}, errors.New("regex: subject exceeds 256 MiB")
	}
	in := patternInput{raw: s, text: s}
	if p.str {
		if !utf8.ValidString(s) {
			return patternInput{}, errors.New("regex: string subject is not valid UTF-8")
		}
		if p.bt != nil {
			in.runes = []rune(s)
			for i := range s {
				in.offsets = append(in.offsets, i)
			}
			in.offsets = append(in.offsets, len(s))
		}
	} else if p.bt != nil {
		in.runes = make([]rune, len(s))
		for i := range len(s) {
			in.runes[i] = rune(s[i])
		}
	} else {
		in.text = latin1(s)
		if in.text != s {
			in.encodedOffsets = make([]int, len(in.text)+1)
			pos := 0
			for i := range len(s) {
				in.encodedOffsets[pos] = i
				pos += utf8.RuneLen(rune(s[i]))
			}
			in.encodedOffsets[pos] = len(s)
		}
	}
	return in, nil
}

func (in patternInput) re2Match(idx []int) *Match {
	m := &Match{Groups: make([]string, len(idx)/2), Spans: make([][2]int, len(idx)/2)}
	for i := range m.Groups {
		start, end := idx[2*i], idx[2*i+1]
		if start >= 0 && in.encodedOffsets != nil {
			start, end = in.encodedOffsets[start], in.encodedOffsets[end]
		}
		m.Spans[i] = [2]int{start, end}
		if start >= 0 {
			m.Groups[i] = in.raw[start:end]
		}
	}
	return m
}

func (p *Pattern) backtrackMatch(in patternInput, match *regexp2.Match) *Match {
	m := &Match{Groups: make([]string, p.groups+1), Spans: make([][2]int, p.groups+1)}
	for i := range m.Groups {
		g := match.GroupByNumber(i)
		if g == nil || len(g.Captures) == 0 {
			m.Spans[i] = [2]int{-1, -1}
			continue
		}
		start, end := g.Index, g.Index+g.Length
		if in.offsets != nil {
			start, end = in.offsets[start], in.offsets[end]
		}
		m.Spans[i] = [2]int{start, end}
		m.Groups[i] = in.raw[start:end]
	}
	return m
}

type templatePart struct {
	text  string
	group int
}

func (p *Pattern) template(s string) ([]templatePart, error) {
	if len(s) > maxSubBytes {
		return nil, errors.New("regex: replacement exceeds 256 MiB")
	}
	if p.str && !utf8.ValidString(s) {
		return nil, errors.New("regex: string replacement is not valid UTF-8")
	}
	var parts []templatePart
	var text strings.Builder
	flush := func() {
		if text.Len() > 0 {
			parts = append(parts, templatePart{text: text.String(), group: -1})
			text.Reset()
		}
	}
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			text.WriteByte(s[i])
			i++
			continue
		}
		start := i
		i++
		if i == len(s) {
			return nil, errors.New("bad escape (end of pattern)")
		}
		c := s[i]
		i++
		group := -1
		switch {
		case c == 'g':
			if i == len(s) || s[i] != '<' {
				return nil, errors.New("missing <")
			}
			name, end, err := groupName(s, i+1, '>')
			if err != nil {
				return nil, err
			}
			i = end
			if strings.Trim(name, "0123456789") == "" {
				group, err = strconv.Atoi(name)
				if err != nil {
					return nil, fmt.Errorf("invalid group reference %s", name)
				}
			} else {
				if err := checkGroupName(name, p.str); err != nil {
					return nil, err
				}
				var ok bool
				group, ok = p.names[name]
				if !ok {
					return nil, fmt.Errorf("unknown group name %q", name)
				}
			}
		case '0' <= c && c <= '9':
			octal := c == '0'
			if i < len(s) && '0' <= s[i] && s[i] <= '9' && c != '0' {
				i++
				octal = c <= '7' && s[i-1] <= '7' && i < len(s) && '0' <= s[i] && s[i] <= '7'
			}
			if octal {
				for i < len(s) && i-start < 4 && '0' <= s[i] && s[i] <= '7' {
					i++
				}
				n, err := strconv.ParseUint(s[start+1:i], 8, 32)
				if err != nil || n > 255 {
					return nil, fmt.Errorf("octal escape value %s outside of range 0-0o377", s[start:i])
				}
				if p.str {
					text.WriteRune(rune(n))
				} else {
					text.WriteByte(byte(n))
				}
				continue
			}
			group, _ = strconv.Atoi(s[start+1 : i])
		case c == '\\':
			text.WriteByte('\\')
			continue
		case strings.ContainsRune("abfnrtv", rune(c)):
			text.WriteByte("\a\b\f\n\r\t\v"[strings.IndexByte("abfnrtv", c)])
			continue
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
			return nil, fmt.Errorf("bad escape \\%c", c)
		default:
			text.WriteString(s[start:i])
			continue
		}
		if group > p.groups {
			return nil, fmt.Errorf("invalid group reference %d", group)
		}
		flush()
		parts = append(parts, templatePart{group: group})
	}
	flush()
	return parts, nil
}
