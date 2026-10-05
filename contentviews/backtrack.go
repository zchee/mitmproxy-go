// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
)

// regexpMatchTimeout bounds every backtracking regular-expression match the
// views run. A match the engine abandons at this limit leaves its text
// untransformed and is reported once through the package logger.
const regexpMatchTimeout = 100 * time.Millisecond

// pySpaceClass spells, as a character-class body, exactly the characters
// Python's \s matches in text patterns.
const pySpaceClass = `\t\n\v\f\r\x1C\x1D\x1E\x1F \x85\xA0` +
	"  -     　"

// isPySpace reports whether Python's str.strip and \s treat r as whitespace.
func isPySpace(r rune) bool {
	switch {
	case r == ' ', '\t' <= r && r <= '\r', 0x1c <= r && r <= 0x1f, r == 0x85, r == 0xa0:
		return true
	case r == 0x1680, 0x2000 <= r && r <= 0x200a, r == 0x2028, r == 0x2029,
		r == 0x202f, r == 0x205f, r == 0x3000:
		return true
	default:
		return false
	}
}

// compileBacktracking compiles a pattern for the backtracking engine with
// the package's match timeout. The patterns are the package's own, so a
// failure to compile is a programming error.
func compileBacktracking(pattern string, opts regexp2.RegexOptions) *regexp2.Regexp {
	re := regexp2.MustCompile(pattern, opts)
	re.MatchTimeout = regexpMatchTimeout
	return re
}

// surrogateDecode decodes bytes the way Python's surrogateescape error
// handler does: every byte that is not part of valid UTF-8 becomes the lone
// surrogate U+DC00 plus the byte, so surrogateEncode restores the input.
func surrogateDecode(data []byte) []rune {
	out := make([]rune, 0, len(data))
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			r = 0xdc00 + rune(data[i])
		}
		out = append(out, r)
		i += size
	}
	return out
}

// surrogateEncode inverts surrogateDecode: the lone surrogates carrying
// escaped bytes become those bytes again, so undecodable input bytes pass
// through a view unchanged.
func surrogateEncode(text []rune) string {
	var b strings.Builder
	b.Grow(len(text))
	for _, r := range text {
		if 0xdc80 <= r && r <= 0xdcff {
			b.WriteByte(byte(r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// pyStripRunes trims the characters Python's str.strip removes from both
// ends.
func pyStripRunes(text []rune) []rune {
	start := 0
	for start < len(text) && isPySpace(text[start]) {
		start++
	}
	end := len(text)
	for end > start && isPySpace(text[end-1]) {
		end--
	}
	return text[start:end]
}

// markSpecialAreas copies text with every special character inside an area
// the pattern matches moved to the private-use page U+E000, as upstream's
// escape_special_areas does, so later replacements cannot touch it. A match
// the engine abandons at the timeout leaves the remaining areas unmarked
// and reports timedOut.
func markSpecialAreas(text []rune, areas *regexp2.Regexp, special string) (marked []rune, timedOut bool) {
	out := slices.Clone(text)
	m, err := areas.FindRunesMatch(text)
	for err == nil && m != nil {
		for i := m.Index; i < m.Index+m.Length; i++ {
			if strings.ContainsRune(special, out[i]) {
				out[i] += 0xe000
			}
		}
		m, err = areas.FindNextMatch(m)
	}
	return out, err != nil
}

// unmarkSpecialAreas inverts markSpecialAreas in place. Like upstream's
// unescape_special_areas, it maps the whole U+E000 page back, including
// characters the input itself carried there.
func unmarkSpecialAreas(text []rune) []rune {
	for i, r := range text {
		if 0xe000 <= r && r <= 0xe0ff {
			text[i] = r - 0xe000
		}
	}
	return text
}

// replaceAllRunes replaces every match of re in text with repl, as
// Python's re.sub does for a literal replacement. A match the engine
// abandons at the timeout returns the text unchanged and reports timedOut.
func replaceAllRunes(re *regexp2.Regexp, text, repl []rune) (replaced []rune, timedOut bool) {
	return replaceAllRunesFunc(re, text, func(*regexp2.Match) []rune { return repl })
}

// replaceAllRunesFunc replaces every match of re in text with what repl
// returns for it, as Python's re.sub does for a replacement with group
// references. A match the engine abandons at the timeout returns the text
// unchanged and reports timedOut.
func replaceAllRunesFunc(re *regexp2.Regexp, text []rune, repl func(*regexp2.Match) []rune) (replaced []rune, timedOut bool) {
	m, err := re.FindRunesMatch(text)
	if err != nil {
		return text, true
	}
	if m == nil {
		return text, false
	}
	out := make([]rune, 0, len(text))
	last := 0
	for m != nil {
		out = append(out, text[last:m.Index]...)
		out = append(out, repl(m)...)
		last = m.Index + m.Length
		m, err = re.FindNextMatch(m)
		if err != nil {
			return text, true
		}
	}
	return append(out, text[last:]...), false
}

// utf8ReplaceDecode decodes bytes the way Python's replace error handler
// does: every maximal subpart of an ill-formed sequence, as CPython and
// the Unicode standard define it, becomes one U+FFFD.
func utf8ReplaceDecode(data []byte) []rune {
	out := make([]rune, 0, len(data))
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			size = invalidPrefixLen(data[i:])
		}
		out = append(out, r)
		i += size
	}
	return out
}

// invalidPrefixLen returns the length of the maximal subpart of the
// ill-formed UTF-8 sequence starting b: the lead byte together with the
// continuation bytes that were still on a path to a valid sequence.
func invalidPrefixLen(b []byte) int {
	lo, hi := byte(0x80), byte(0xbf)
	var continuations int
	switch c := b[0]; {
	case c < 0xe0:
		// A continuation byte, an overlong lead or a two-byte lead whose
		// continuation is missing or invalid.
		return 1
	case c == 0xe0:
		lo, continuations = 0xa0, 2
	case c <= 0xec:
		continuations = 2
	case c == 0xed:
		hi, continuations = 0x9f, 2
	case c <= 0xef:
		continuations = 2
	case c == 0xf0:
		lo, continuations = 0x90, 3
	case c <= 0xf3:
		continuations = 3
	case c == 0xf4:
		hi, continuations = 0x8f, 3
	default:
		return 1
	}
	n := 1
	if len(b) > 1 && lo <= b[1] && b[1] <= hi {
		n = 2
		for n < len(b) && n <= continuations && b[n]&0xc0 == 0x80 {
			n++
		}
	}
	return n
}

// pySplitLines splits text into lines with their line ends kept, at
// exactly the boundaries Python's str.splitlines uses.
func pySplitLines(text []rune) [][]rune {
	var lines [][]rune
	start := 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			lines = append(lines, text[start:i+1])
			start = i + 1
		case '\r':
			if i+1 < len(text) && text[i+1] == '\n' {
				i++
			}
			lines = append(lines, text[start:i+1])
			start = i + 1
		}
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}
