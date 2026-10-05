// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"github.com/dlclark/regexp2"
)

// pyWordClass spells, as a character-class body, the characters Python's
// \w matches in text patterns: letters, numerals and the underscore.
const pyWordClass = `\p{L}\p{N}_`

// jsSpecialAreas matches the regions whose content the JavaScript
// beautifier must not touch, as upstream's SPECIAL_AREAS lists them:
// regular-expression literals recognised by what precedes and follows
// them, quoted strings whose line breaks are escaped, template literals,
// comments and for-loop heads.
var jsSpecialAreas = compileBacktracking(
	`(?<=[^`+pyWordClass+pySpaceClass+`)])[`+pySpaceClass+`]*/(?:[^\n/]|(?<!\\)(?:\\\\)*\\/)+?/(?=[gimsuy]{0,6}[`+pySpaceClass+`]*(?:[;,).\n]|$))`+
		`|'(?:.|(?<=\\)\n)*?(?<!\\)(?:\\\\)*'`+
		`|"(?:.|(?<=\\)\n)*?(?<!\\)(?:\\\\)*"`+
		"|`[\\s\\S]*?(?<!\\\\)(?:\\\\\\\\)*`"+
		`|/\*[\s\S]*?\*/`+
		`|//.*?$`+
		`|for\(.*?\)`,
	regexp2.Multiline,
)

// The brace and semicolon rewrites of upstream's beautify, in its order.
var (
	jsOpenBrace  = compileBacktracking(`[`+pySpaceClass+`]*\{[`+pySpaceClass+`]*(?!};)`, regexp2.None)
	jsSemicolon  = compileBacktracking(`[`+pySpaceClass+`]*;[`+pySpaceClass+`]*`, regexp2.None)
	jsCloseBrace = compileBacktracking(`(?<!\{)[`+pySpaceClass+`]*}(;)?[`+pySpaceClass+`]*`, regexp2.None)
)

// JavaScript reformats a script's braces, semicolons and indentation, as
// upstream's beautifier does, while regular-expression literals, strings,
// template literals, comments and for-loop heads stay untouched.
type JavaScript struct{}

// Name returns the registered view name.
func (JavaScript) Name() string { return "JavaScript" }

// SyntaxHighlight returns the view's highlighting language.
func (JavaScript) SyntaxHighlight() string { return "javascript" }

// RenderPriority prefers nonempty bodies with a JavaScript content type.
func (JavaScript) RenderPriority(data []byte, metadata Metadata) float64 {
	switch metadata.ContentType {
	case "application/x-javascript", "application/javascript", "text/javascript":
		if len(data) != 0 {
			return 1
		}
	}
	return 0
}

// Prettify beautifies the script: blocks get their own lines and two-space
// indentation while the protected areas keep their text. Bytes that are
// not valid UTF-8 become replacement characters, as Python's replace
// error handler has it. A pattern the engine abandons at the match timeout
// leaves its area unmarked or its rewrite unapplied, and one warning goes
// to the package logger.
func (JavaScript) Prettify(data []byte, metadata Metadata) (string, error) {
	text := utf8ReplaceDecode(data)
	marked, timedOut := markSpecialAreas(text, jsSpecialAreas, "{};\n")
	var to bool
	marked, to = replaceAllRunes(jsOpenBrace, marked, []rune(" {\n"))
	timedOut = timedOut || to
	marked, to = replaceAllRunes(jsSemicolon, marked, []rune(";\n"))
	timedOut = timedOut || to
	marked, to = replaceAllRunesFunc(jsCloseBrace, marked, func(m *regexp2.Match) []rune {
		out := []rune("\n}")
		if group := m.GroupByNumber(1); group != nil && group.Length > 0 {
			out = append(out, ';')
		}
		return append(out, '\n')
	})
	timedOut = timedOut || to
	if timedOut {
		logSink().Warn("JavaScript beautification left text unformatted: a pattern exceeded the match timeout",
			"view", "javascript", "timeout", regexpMatchTimeout)
	}
	var out []rune
	level := 0
	for _, line := range pySplitLines(marked) {
		switch {
		case len(line) >= 2 && line[len(line)-2] == '{' && line[len(line)-1] == '\n':
			out = appendIndent(out, level)
			out = append(out, line...)
			level++
		case len(line) > 0 && line[0] == '}':
			level--
			out = appendIndent(out, level)
			out = append(out, line...)
		default:
			out = appendIndent(out, level)
			out = append(out, line...)
		}
	}
	return string(unmarkSpecialAreas(out)), nil
}

// appendIndent appends two spaces per indentation level; a negative level
// appends nothing, as Python's string repetition has it.
func appendIndent(out []rune, level int) []rune {
	for range max(level, 0) {
		out = append(out, ' ', ' ')
	}
	return out
}
