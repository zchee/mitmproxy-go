// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package command

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// lexSpace holds the characters that separate the words of a command line.
// Other Unicode whitespace is part of a word, as in mitmproxy's lexer.
const lexSpace = " \r\n\t"

// Lex splits a possibly partial command line into tokens, as mitmproxy's
// command_lexer.expr does. Every input is valid, and joining the tokens gives
// the line back after its tabs are expanded. A token is one of:
//
//   - a quoted string: a single or double quote up to and including the next
//     quote of the same kind, or up to the end of the line when there is none;
//     a backslash does not escape the quote;
//   - a run of spaces, carriage returns and newlines;
//   - a run of other characters, ending before a quote or a separator.
//
// Like pyparsing, which runs str.expandtabs on its input before parsing, Lex
// first replaces each tab with spaces up to the next multiple of eight
// columns, so a tab inside a quoted string reaches the command as spaces.
func Lex(line string) []string {
	s := expandTabs(line)
	var tokens []string
	for i := 0; i < len(s); {
		var n int
		switch c := s[i]; {
		case c == '"' || c == '\'':
			if j := strings.IndexByte(s[i+1:], c); j >= 0 {
				n = j + 2
			} else {
				n = len(s) - i
			}
		case strings.IndexByte(lexSpace, c) >= 0:
			n = len(s[i:]) - len(strings.TrimLeft(s[i:], lexSpace))
		default:
			n = strings.IndexAny(s[i:], lexSpace+`'"`)
			if n < 0 {
				n = len(s) - i
			}
		}
		tokens = append(tokens, s[i:i+n])
		i += n
	}
	return tokens
}

// Quote returns s as one command-line token that [Unquote] turns back into s.
// A non-empty s without quotes or separators is returned as it is; otherwise
// it is wrapped in double quotes, or in single quotes when it holds a double
// quote. When it holds both, its double quotes are written as the four
// characters \x22 inside double quotes, which Unquote leaves as they are and
// a str argument decodes back to a double quote, as in mitmproxy.
func Quote(s string) string {
	switch {
	case s != "" && !strings.ContainsAny(s, `'"`+lexSpace):
		return s
	case !strings.Contains(s, `"`):
		return `"` + s + `"`
	case !strings.Contains(s, `'`):
		return `'` + s + `'`
	default:
		return `"` + strings.ReplaceAll(s, `"`, `\x22`) + `"`
	}
}

// Unquote removes the quotes around a token: when s is at least two bytes
// long and starts and ends with the same quote character, the two are
// removed; any other s is returned as it is.
func Unquote(s string) string {
	if len(s) > 1 && (s[0] == '"' || s[0] == '\'') && s[0] == s[len(s)-1] {
		return s[1 : len(s)-1]
	}
	return s
}

// expandTabs is Python's str.expandtabs() with the default tab size of 8:
// each tab becomes spaces up to the next multiple of 8 columns, where a
// column is one code point and CR and LF reset the column to 0. Bytes that
// are not valid UTF-8 are kept as they are and take one column each.
func expandTabs(s string) string {
	if !strings.Contains(s, "\t") {
		return s
	}
	var b strings.Builder
	col := 0
	for len(s) > 0 {
		_, size := utf8.DecodeRuneInString(s)
		switch s[0] {
		case '\t':
			n := 8 - col%8
			b.WriteString(strings.Repeat(" ", n))
			col += n
		case '\n', '\r':
			b.WriteByte(s[0])
			col = 0
		default:
			b.WriteString(s[:size])
			col++
		}
		s = s[size:]
	}
	return b.String()
}

// isSpace reports whether Python's str.isspace() holds for s: s is not empty
// and every code point is Unicode White_Space or one of the ASCII separators
// U+001C to U+001F, which Python counts as whitespace through their
// bidirectional class. mitmproxy uses it to tell separator tokens from
// arguments, so a word of other whitespace, such as a vertical tab on its
// own, is a separator too.
func isSpace(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !isSpaceRune(r) {
			return false
		}
	}
	return true
}

// isSpaceRune reports whether Python's str.isspace() holds for the single
// code point r. str.strip() trims these same code points.
func isSpaceRune(r rune) bool {
	return unicode.Is(unicode.White_Space, r) || ('\x1c' <= r && r <= '\x1f')
}
