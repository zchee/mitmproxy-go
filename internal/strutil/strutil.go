// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package strutil holds the string and byte helpers of mitmproxy's
// mitmproxy/utils/strutils.py: escaping bytes for display and back, binary
// and XML sniffing, hex dumps, and protecting regions of source text from
// regular-expression rewrites.
//
// Upstream's always_bytes and always_str are not ported: in Go they are the
// []byte and string conversions, and the text codecs they select belong to
// the callers that need them.
package strutil

import (
	"errors"
	"fmt"
	"iter"
	"strings"
	"unicode/utf8"
)

const hexDigits = "0123456789abcdef"

// spacingEscapes holds the escapes BytesToEscapedStr uses for whitespace.
var spacingEscapes = map[byte]string{'\t': `\t`, '\n': `\n`, '\r': `\r`}

// EscapeControlCharacters replaces each ASCII control character (U+0000 to
// U+001F and U+007F) in text with ".". If keepSpacing is true, tab, line
// feed and carriage return are kept.
//
// Bytes outside ASCII, including invalid UTF-8, are left unchanged.
func EscapeControlCharacters(text string, keepSpacing bool) string {
	first := -1
	for i := range len(text) {
		if isEscapedControl(text[i], keepSpacing) {
			first = i
			break
		}
	}
	if first < 0 {
		return text
	}
	b := []byte(text)
	for i := first; i < len(b); i++ {
		if isEscapedControl(b[i], keepSpacing) {
			b[i] = '.'
		}
	}
	return string(b)
}

func isEscapedControl(c byte, keepSpacing bool) bool {
	if keepSpacing && (c == '\t' || c == '\n' || c == '\r') {
		return false
	}
	return c < 0x20 || c == 0x7f
}

// BytesToEscapedStr returns data as a string that is safe to show to a
// user, escaped the way a Python bytes literal is: backslash, tab, line
// feed and carriage return become \\, \t, \n and \r, and every other byte
// outside printable ASCII becomes \xNN.
//
// Double quotes are never escaped. Single quotes are escaped as \' only if
// escapeSingleQuotes is true, so "'" + BytesToEscapedStr(data, false, true)
// + "'" is a valid Python string literal. If keepSpacing is true, tab, line
// feed and carriage return are kept as they are.
//
// Unlike upstream, every backslash is kept: upstream post-processes the
// escaped text with a regular expression whose repeated group keeps only its
// last repetition, so two or more backslashes before a quote (or, with
// keepSpacing, before a line feed, carriage return or tab) lose all but one
// escaped pair, and the text no longer decodes to data.
func BytesToEscapedStr(data []byte, keepSpacing, escapeSingleQuotes bool) string {
	var b strings.Builder
	b.Grow(len(data))
	for _, c := range data {
		switch {
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\'' && escapeSingleQuotes:
			b.WriteString(`\'`)
		case c == '\t' || c == '\n' || c == '\r':
			if keepSpacing {
				b.WriteByte(c)
				continue
			}
			b.WriteString(spacingEscapes[c])
		case c < 0x20 || c >= 0x7f:
			b.WriteString(`\x`)
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0xf])
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// EscapedStrToBytes decodes the escape sequences of a Python bytes literal
// in data and returns the bytes, as Python's codecs.escape_decode does.
// Characters that are not escaped stand for their UTF-8 encoding.
//
// The recognised escapes are \\, \', \", \a, \b, \f, \n, \r, \t, \v, one to
// three octal digits (keeping the low 8 bits), \xNN, and a backslash before
// a line feed, which removes both. A backslash before any other character
// is kept. It returns an error for a \x escape without two hex digits and
// for a trailing backslash.
func EscapedStrToBytes(data string) ([]byte, error) {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		start := i
		i++
		if i == len(data) {
			return nil, errors.New(`Trailing \ in string`) //nolint:staticcheck // Python's codec message, shown to users verbatim.
		}
		switch c := data[i]; c {
		case '\n':
		case '\\', '\'', '"':
			out = append(out, c)
		case 'a':
			out = append(out, '\a')
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'v':
			out = append(out, '\v')
		case '0', '1', '2', '3', '4', '5', '6', '7':
			v := int(c - '0')
			for n := 0; n < 2 && i+1 < len(data) && '0' <= data[i+1] && data[i+1] <= '7'; n++ {
				i++
				v = v*8 + int(data[i]-'0')
			}
			out = append(out, byte(v))
		case 'x':
			if i+2 >= len(data) {
				return nil, fmt.Errorf(`invalid \x escape at position %d`, start)
			}
			hi, ok1 := unhex(data[i+1])
			lo, ok2 := unhex(data[i+2])
			if !ok1 || !ok2 {
				return nil, fmt.Errorf(`invalid \x escape at position %d`, start)
			}
			out = append(out, hi<<4|lo)
			i += 2
		default:
			// An unknown escape keeps its backslash; the character after it
			// is read again as ordinary input.
			out = append(out, '\\')
			i--
		}
	}
	return out, nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// sniffLen is how many leading bytes IsMostlyBin inspects.
const sniffLen = 100

// IsMostlyBin reports whether s looks like binary data rather than text.
//
// It inspects about the first 100 bytes, extended by up to three bytes so
// that a UTF-8 sequence is not cut in half. Text is mostly printable ASCII,
// or valid UTF-8 with few ASCII control characters.
func IsMostlyBin(s []byte) bool {
	if len(s) == 0 {
		return false
	}
	if len(s) > sniffLen {
		cut := sniffLen
		for i := sniffLen; i < min(sniffLen+4, len(s)); i++ {
			if s[i]>>6 != 0b10 {
				// A new character starts here, so cut just before it.
				cut = i
				break
			}
		}
		s = s[:cut]
	}

	var low, high int
	for _, c := range s {
		switch {
		case c < 9 || (13 < c && c < 32):
			low++
		case c > 126:
			high++
		}
	}
	ascii := len(s) - low - high

	// Mostly printable ASCII is text.
	if float64(ascii)/float64(len(s)) > 0.7 {
		return false
	}
	// UTF-8 without too many ASCII control characters is text. Any byte
	// string of control characters is valid UTF-8, hence the ratio check.
	if float64(ascii+high)/float64(len(s)) > 0.95 && utf8.Valid(s) {
		return false
	}
	return true
}

// IsXML reports whether the first byte of s that is not XML whitespace
// (space, tab, carriage return or line feed) is "<".
func IsXML(s []byte) bool {
	for _, c := range s {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		}
		return c == '<'
	}
	return false
}

// CleanHangingNewline removes one trailing line feed, which many editors
// add silently to the last line of a document.
func CleanHangingNewline(t string) string {
	return strings.TrimSuffix(t, "\n")
}

// HexDumpLine is one line of a hex dump covering up to 16 bytes.
type HexDumpLine struct {
	// Offset is the position of the first byte as 10 lowercase hex digits.
	Offset string
	// Hex holds the bytes as space-separated hex pairs, padded to 47
	// characters.
	Hex string
	// Text holds the bytes with each one outside printable ASCII shown as
	// ".".
	Text string
}

// HexDump returns the lines of a hex dump of s, 16 bytes per line.
func HexDump(s []byte) iter.Seq[HexDumpLine] {
	return func(yield func(HexDumpLine) bool) {
		for i := 0; i < len(s); i += 16 {
			part := s[i:min(i+16, len(s))]
			hex := make([]byte, 0, 47)
			text := make([]byte, len(part))
			for j, c := range part {
				if j > 0 {
					hex = append(hex, ' ')
				}
				hex = append(hex, hexDigits[c>>4], hexDigits[c&0xf])
				if c < 0x20 || c >= 0x7f {
					c = '.'
				}
				text[j] = c
			}
			line := HexDumpLine{
				Offset: fmt.Sprintf("%010x", i),
				Hex:    fmt.Sprintf("%-47s", hex),
				Text:   string(text),
			}
			if !yield(line) {
				return
			}
		}
	}
}

// AreaFinder locates special areas in a text. *regexp.Regexp implements it;
// an engine with lookaround, which upstream's patterns use and Go's regexp
// lacks, can be adapted to it.
type AreaFinder interface {
	FindAllStringIndex(s string, n int) [][]int
}

// SplitSpecialAreas splits data into code and special areas, alternating
// and starting with code: [code, area, code, area, ..., code]. Joining the
// parts gives data back.
//
// Upstream joins its patterns with "|" in one capturing group and compiles
// them with re.MULTILINE; a *regexp.Regexp used here needs the (?m) flag
// for the same behaviour.
func SplitSpecialAreas(data string, areas AreaFinder) []string {
	matches := areas.FindAllStringIndex(data, -1)
	parts := make([]string, 0, 2*len(matches)+1)
	prev := 0
	for _, m := range matches {
		parts = append(parts, data[prev:m[0]], data[m[0]:m[1]])
		prev = m[1]
	}
	return append(parts, data[prev:])
}

// privateUseBase is the start of the Unicode private use area that
// EscapeSpecialAreas moves protected characters into.
const privateUseBase = 0xe000

// EscapeSpecialAreas replaces every character of controlCharacters that
// occurs inside a special area with the private use character
// U+E000 + its code point, so that later regular-expression rewrites of the
// code leave the special areas alone. UnescapeSpecialAreas reverts it.
//
// Every character in controlCharacters must lie between U+0001 and U+00FF.
func EscapeSpecialAreas(data string, areas AreaFinder, controlCharacters string) string {
	var b strings.Builder
	b.Grow(len(data))
	for i, part := range SplitSpecialAreas(data, areas) {
		if i%2 == 0 {
			b.WriteString(part)
			continue
		}
		b.WriteString(strings.Map(func(r rune) rune {
			if r > 0 && r < 0x100 && strings.ContainsRune(controlCharacters, r) {
				return r + privateUseBase
			}
			return r
		}, part))
	}
	return b.String()
}

// UnescapeSpecialAreas maps every character from U+E000 to U+E0FF back to
// U+0000 to U+00FF, inverting EscapeSpecialAreas.
func UnescapeSpecialAreas(data string) string {
	return strings.Map(func(r rune) rune {
		if privateUseBase <= r && r <= privateUseBase+0xff {
			return r - privateUseBase
		}
		return r
	}, data)
}

// CutAfterNLines returns content up to and including its n-th line feed, or
// all of content if it has fewer lines. It panics if n is not positive.
func CutAfterNLines(content string, n int) string {
	if n <= 0 {
		panic(fmt.Sprintf("strutil: CutAfterNLines with n = %d, want n > 0", n))
	}
	pos := -1
	for range n {
		next := strings.IndexByte(content[pos+1:], '\n')
		if next < 0 {
			return content
		}
		pos += next + 1
	}
	return content[:pos+1]
}
