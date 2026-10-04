// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package options

import (
	"slices"
	"strings"
	"unicode"
)

// dedent is Python's textwrap.dedent: lines consisting only of spaces and
// tabs are emptied, and the longest leading run of spaces and tabs shared by
// all other lines is removed.
//
// mitmproxy runs every option help text through it. When the first line of
// a help text starts right after the opening quotes, it has no indentation,
// the common margin is empty, and the indentation of the following lines is
// kept; the resulting runs of spaces are part of the help text upstream.
func dedent(text string) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if strings.Trim(l, " \t") == "" {
			lines[i] = ""
		}
	}
	var margin string
	haveMargin := false
	for _, l := range lines {
		if l == "" {
			continue
		}
		indent := l[:len(l)-len(strings.TrimLeft(l, " \t"))]
		switch {
		case !haveMargin:
			margin, haveMargin = indent, true
		case strings.HasPrefix(indent, margin):
		case strings.HasPrefix(margin, indent):
			margin = indent
		default:
			i := 0
			for i < len(margin) && i < len(indent) && margin[i] == indent[i] {
				i++
			}
			margin = margin[:i]
		}
	}
	if margin != "" {
		for i, l := range lines {
			lines[i] = strings.TrimPrefix(l, margin)
		}
	}
	return strings.Join(lines, "\n")
}

// wrapWidth is the line width of Python's textwrap.wrap default.
const wrapWidth = 70

// isWrapSpace reports whether r is whitespace for textwrap, which only
// considers ASCII whitespace.
func isWrapSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

// isWordChar reports whether r matches Python's \w.
func isWordChar(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsNumber(r)
}

// isLetter reports whether r matches Python's [^\d\W]: a word character that
// is not a decimal digit.
func isLetter(r rune) bool {
	return isWordChar(r) && !unicode.IsDigit(r)
}

// isWordPunct reports whether r matches textwrap's word_punct class
// [\w!"'&.,?].
func isWordPunct(r rune) bool {
	return isWordChar(r) || strings.ContainsRune(`!"'&.,?`, r)
}

// emDashAt reports whether t[i:] starts with two or more hyphens followed by
// a word character, and returns the index just past the hyphens.
func emDashAt(t []rune, i int) (int, bool) {
	j := i
	for j < len(t) && t[j] == '-' {
		j++
	}
	if j-i < 2 || j >= len(t) || !isWordChar(t[j]) {
		return 0, false
	}
	return j, true
}

func letterAt(t []rune, i int) bool { return i >= 0 && i < len(t) && isLetter(t[i]) }

// splitChunks is textwrap.TextWrapper._split with break_on_hyphens set: it
// cuts t into runs of whitespace and words, where a word may be split
// after a hyphen that joins two letter sequences, and an em-dash ("--")
// between words is a chunk of its own. It reproduces the matching order of
// textwrap's wordsep_re, which needs lookbehind and so cannot be written
// as an RE2 expression.
func splitChunks(t []rune) [][]rune {
	var chunks [][]rune
	for i := 0; i < len(t); {
		start := i
		switch {
		case isWrapSpace(t[i]):
			for i < len(t) && isWrapSpace(t[i]) {
				i++
			}
		default:
			if i > 0 && isWordPunct(t[i-1]) {
				if j, ok := emDashAt(t, i); ok {
					i = j
					break
				}
			}
			// The shortest run of non-whitespace that ends at one of the
			// three word boundaries of wordsep_re. The run always ends at
			// whitespace or at the end of the text at the latest.
			for j := i + 1; ; j++ {
				if j < len(t) && t[j] == '-' &&
					(letterAt(t, j-2) && letterAt(t, j-1) || letterAt(t, j-3) && j-2 >= 0 && t[j-2] == '-' && letterAt(t, j-1)) &&
					(letterAt(t, j+1) && letterAt(t, j+2) || letterAt(t, j+1) && j+2 < len(t) && t[j+2] == '-' && letterAt(t, j+3)) {
					i = j + 1
					break
				}
				if j == len(t) || isWrapSpace(t[j]) {
					i = j
					break
				}
				if isWordPunct(t[j-1]) {
					if _, ok := emDashAt(t, j); ok {
						i = j
						break
					}
				}
			}
		}
		chunks = append(chunks, t[start:i])
	}
	return chunks
}

func isBlankChunk(c []rune) bool {
	return strings.TrimSpace(string(c)) == ""
}

// wrap is Python's textwrap.wrap(text) with its default settings: width 70,
// tabs expanded, every whitespace character replaced by a space, whitespace
// dropped at line boundaries, long words broken, preferably after a hyphen.
func wrap(text string) []string {
	text = expandTabs(text)
	t := []rune(text)
	for i, r := range t {
		if isWrapSpace(r) {
			t[i] = ' '
		}
	}
	chunks := splitChunks(t)

	var lines []string
	for len(chunks) > 0 {
		var cur [][]rune
		curLen := 0
		if isBlankChunk(chunks[0]) && len(lines) > 0 {
			chunks = chunks[1:]
		}
		for len(chunks) > 0 && curLen+len(chunks[0]) <= wrapWidth {
			cur = append(cur, chunks[0])
			curLen += len(chunks[0])
			chunks = chunks[1:]
		}
		if len(chunks) > 0 && len(chunks[0]) > wrapWidth {
			// _handle_long_word with break_long_words and break_on_hyphens.
			spaceLeft := max(wrapWidth-curLen, 1)
			chunk := chunks[0]
			end := spaceLeft
			if len(chunk) > spaceLeft {
				if h := lastHyphen(chunk[:spaceLeft]); h > 0 && hasNonHyphen(chunk[:h]) {
					end = h + 1
				}
			}
			cur = append(cur, chunk[:end])
			chunks[0] = chunk[end:]
		}
		if len(cur) > 0 && isBlankChunk(cur[len(cur)-1]) {
			cur = cur[:len(cur)-1]
		}
		if len(cur) > 0 {
			var b strings.Builder
			for _, c := range cur {
				b.WriteString(string(c))
			}
			lines = append(lines, b.String())
		}
	}
	return lines
}

func lastHyphen(c []rune) int {
	for i, v := range slices.Backward(c) {
		if v == '-' {
			return i
		}
	}
	return -1
}

func hasNonHyphen(c []rune) bool {
	for _, r := range c {
		if r != '-' {
			return true
		}
	}
	return false
}

// expandTabs is Python's str.expandtabs() with the default tab size of 8.
func expandTabs(s string) string {
	if !strings.ContainsRune(s, '\t') {
		return s
	}
	var b strings.Builder
	col := 0
	for _, r := range s {
		switch r {
		case '\t':
			n := 8 - col%8
			b.WriteString(strings.Repeat(" ", n))
			col += n
		case '\n', '\r':
			b.WriteRune(r)
			col = 0
		default:
			b.WriteRune(r)
			col++
		}
	}
	return b.String()
}
