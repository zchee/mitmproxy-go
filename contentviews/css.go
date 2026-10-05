// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"github.com/dlclark/regexp2"
)

// cssSpecialAreas matches the regions whose content the CSS beautifier
// must not touch: quoted strings up to an unescaped quote, block comments
// and line comments, as upstream's CSS_SPECIAL_AREAS lists them.
var cssSpecialAreas = compileBacktracking(
	`'.*?(?<!\\)(?:\\\\)*'|".*?(?<!\\)(?:\\\\)*"|/\*[\s\S]*?\*/|//.*?$`,
	regexp2.Multiline,
)

// The whitespace rewrites of upstream's beautify, in its order.
var (
	cssSemicolon  = compileBacktracking(`[`+pySpaceClass+`]*;[`+pySpaceClass+`]*`, regexp2.None)
	cssOpenBrace  = compileBacktracking(`[`+pySpaceClass+`]*\{[`+pySpaceClass+`]*`, regexp2.None)
	cssCloseBrace = compileBacktracking(`[`+pySpaceClass+`]*}[`+pySpaceClass+`]*`, regexp2.None)
	cssColon      = compileBacktracking(`[`+pySpaceClass+`]*:[`+pySpaceClass+`]*(?=[^{]+})`, regexp2.None)
	cssComma      = compileBacktracking(`[`+pySpaceClass+`]*,[`+pySpaceClass+`]*`, regexp2.None)
	cssDeindent   = compileBacktracking("\n[ \t]+", regexp2.None)
	cssIndent     = compileBacktracking("\n(?![}\n])(?=[^{]*})", regexp2.None)
)

// CSS reformats a style sheet's whitespace, as upstream's pure-Python CSS
// prettifier does: it works with any input and modifies whitespace only.
type CSS struct{}

// Name returns the registered view name.
func (CSS) Name() string { return "CSS" }

// SyntaxHighlight returns the view's highlighting language.
func (CSS) SyntaxHighlight() string { return "css" }

// RenderPriority prefers nonempty text/css bodies.
func (CSS) RenderPriority(data []byte, metadata Metadata) float64 {
	if len(data) != 0 && metadata.ContentType == "text/css" {
		return 1
	}
	return 0
}

// Prettify beautifies the style sheet: rules and declarations get their own
// lines and indentation while quoted strings and comments stay untouched.
// Undecodable bytes pass through unchanged. A pattern the engine abandons
// at the match timeout leaves its area unmarked or its rewrite unapplied,
// and one warning goes to the package logger.
func (CSS) Prettify(data []byte, metadata Metadata) (string, error) {
	text := pyStripRunes(surrogateDecode(data))
	marked, timedOut := markSpecialAreas(text, cssSpecialAreas, "{};:")
	rewrites := []struct {
		re   *regexp2.Regexp
		repl string
	}{
		{cssSemicolon, ";\n"},
		{cssOpenBrace, " {\n"},
		{cssCloseBrace, "\n}\n\n"},
		{cssColon, ": "},
		{cssComma, ", "},
		{cssDeindent, "\n"},
		{cssIndent, "\n    "},
	}
	for _, rewrite := range rewrites {
		var to bool
		marked, to = replaceAllRunes(rewrite.re, marked, []rune(rewrite.repl))
		timedOut = timedOut || to
	}
	if timedOut {
		logSink().Warn("CSS beautification left text unformatted: a pattern exceeded the match timeout",
			"view", "css", "timeout", regexpMatchTimeout)
	}
	out := unmarkSpecialAreas(marked)
	end := len(out)
	for end > 0 && out[end-1] == '\n' {
		end--
	}
	return surrogateEncode(out[:end]) + "\n", nil
}
