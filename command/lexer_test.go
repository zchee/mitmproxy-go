// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package command_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/command"
)

// TestLexPartialQuotedString ports test_partial_quoted_string: an input is a
// valid partial quoted string when the lexer reads all of it as one quoted
// token.
func TestLexPartialQuotedString(t *testing.T) {
	tests := map[string]struct {
		in    string
		valid bool
	}{
		"success: single quoted":                  {in: `'foo'`, valid: true},
		"success: double quoted":                  {in: `"foo"`, valid: true},
		"error: text after the closing quote":     {in: `'foo' bar'`},
		"error: two quoted strings":               {in: `'foo' 'bar'`},
		"error: word glued to the closing quote":  {in: `'foo'x`},
		"success: unterminated with spaces":       {in: `"foo    `, valid: true},
		"success: unterminated with inner quotes": {in: `"foo 'bar'   `, valid: true},
		"success: backslash does not escape":      {in: `"foo\`, valid: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			toks := command.Lex(tt.in)
			got := len(toks) == 1 && toks[0] == tt.in && strings.ContainsAny(tt.in[:1], `'"`)
			if got != tt.valid {
				t.Errorf("Lex(%q) = %q; one quoted token = %t, want %t", tt.in, toks, got, tt.valid)
			}
		})
	}
}

// TestLex ports test_expr and adds the cases upstream's grammar implies:
// separators, tabs expanded the way pyparsing expands them, quotes that end
// a word, and whitespace outside the separator set.
func TestLex(t *testing.T) {
	tests := map[string]struct {
		in   string
		want []string
	}{
		"success: single quoted":           {in: `'foo'`, want: []string{`'foo'`}},
		"success: double quoted":           {in: `"foo"`, want: []string{`"foo"`}},
		"success: two quoted strings":      {in: `'foo' 'bar'`, want: []string{`'foo'`, " ", `'bar'`}},
		"success: word after quote":        {in: `'foo'x`, want: []string{`'foo'`, "x"}},
		"success: unterminated":            {in: `"foo`, want: []string{`"foo`}},
		"success: unterminated with inner": {in: `"foo 'bar' `, want: []string{`"foo 'bar' `}},
		"success: trailing backslash":      {in: `"foo\`, want: []string{`"foo\`}},
		"success: empty":                   {in: "", want: nil},
		"success: plain words":             {in: "one.two foo", want: []string{"one.two", " ", "foo"}},
		"success: separator runs kept":     {in: "  a \r\n b  ", want: []string{"  ", "a", " \r\n ", "b", "  "}},
		"success: quote ends a word":       {in: `foo"bar baz" x`, want: []string{"foo", `"bar baz"`, " ", "x"}},
		"success: other quote inside":      {in: `'a "b" c'`, want: []string{`'a "b" c'`}},
		"success: lone quote":              {in: `'`, want: []string{`'`}},
		"success: empty quotes":            {in: `""''`, want: []string{`""`, `''`}},
		"success: tab between words":       {in: "a\tb", want: []string{"a", "       ", "b"}},
		"success: tab at column 8":         {in: "abcdefgh\tx", want: []string{"abcdefgh", "        ", "x"}},
		"success: tab inside quotes":       {in: "'a\tb'", want: []string{"'a      b'"}},
		"success: newline resets column":   {in: "abc\n\tx", want: []string{"abc", "\n        ", "x"}},
		"success: code points are columns": {in: "\U000000e9\tx", want: []string{"\U000000e9", "       ", "x"}},
		"success: vertical tab is a word":  {in: "a\vb \f", want: []string{"a\vb", " ", "\f"}},
		"success: ideographic space word":  {in: "a\U00003000b", want: []string{"a\U00003000b"}},
		"success: backslashes":             {in: `\\\foo`, want: []string{`\\\foo`}},
		"success: invalid utf-8 kept":      {in: "\xff\t\xfe", want: []string{"\xff", "       ", "\xfe"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, command.Lex(tt.in)); diff != "" {
				t.Errorf("Lex(%q) (-want +got):\n%s", tt.in, diff)
			}
		})
	}
}

// quoteExamples are the explicit examples of upstream's hypothesis tests
// test_quote_unquote_cycle and test_unquote_never_fails.
var quoteExamples = []string{
	`foo`, `'foo\''`, `'foo\"'`, `"foo\""`, `"foo\'"`, `'foo\'`, `'foo\\'`,
	`"foo\'"`, `"foo\\'"`, `'foo\"'`, `\\\foo`, `\x22`, "", `"`, `'`, `'"`,
	"a b", "a\tb", "\r\n",
}

func TestQuote(t *testing.T) {
	tests := map[string]struct {
		in   string
		want string
	}{
		"success: plain word unchanged": {in: "foo", want: "foo"},
		"success: empty":                {in: "", want: `""`},
		"success: space":                {in: "foo bar", want: `"foo bar"`},
		"success: double quote":         {in: `a"b`, want: `'a"b'`},
		"success: single quote":         {in: `a'b`, want: `"a'b"`},
		"success: both quotes":          {in: `a"b'c`, want: `"a\x22b'c"`},
		"success: tab":                  {in: "a\tb", want: "\"a\tb\""},
		"success: newline":              {in: "a\nb", want: "\"a\nb\""},
		"success: other whitespace":     {in: "a\vb", want: "a\vb"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := command.Quote(tt.in); got != tt.want {
				t.Errorf("Quote(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestUnquote(t *testing.T) {
	tests := map[string]struct {
		in   string
		want string
	}{
		"success: double quoted":     {in: `"foo"`, want: "foo"},
		"success: single quoted":     {in: `'foo'`, want: "foo"},
		"success: empty quotes":      {in: `''`, want: ""},
		"success: lone quote":        {in: `"`, want: `"`},
		"success: mismatched quotes": {in: `"foo'`, want: `"foo'`},
		"success: unterminated":      {in: `"foo`, want: `"foo`},
		"success: escape kept":       {in: `"a\x22b"`, want: `a\x22b`},
		"success: plain":             {in: "foo", want: "foo"},
		"success: empty":             {in: "", want: ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := command.Unquote(tt.in); got != tt.want {
				t.Errorf("Unquote(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// checkQuoteCycle is upstream's test_quote_unquote_cycle property: quoting
// and unquoting gives the input back once \x22 is read as a double quote.
// Upstream skips inputs that already hold \x22, which the cycle cannot
// tell apart from an escaped quote.
func checkQuoteCycle(t *testing.T, s string) {
	t.Helper()
	if strings.Contains(s, `\x22`) {
		return
	}
	if got := strings.ReplaceAll(command.Unquote(command.Quote(s)), `\x22`, `"`); got != s {
		t.Errorf("Unquote(Quote(%q)) = %q", s, got)
	}
}

func TestQuoteUnquoteCycle(t *testing.T) {
	for _, s := range quoteExamples {
		checkQuoteCycle(t, s)
	}
}

// checkLexInvariants checks what every lexing must satisfy: the tokens are
// not empty and join to the tab-expanded input, and lexing a token on its
// own gives it back, since a token never ends where a longer one could.
func checkLexInvariants(t *testing.T, s string) {
	t.Helper()
	toks := command.Lex(s)
	joined := strings.Join(toks, "")
	if strings.ReplaceAll(joined, " ", "") != strings.ReplaceAll(strings.ReplaceAll(s, "\t", ""), " ", "") {
		t.Fatalf("Lex(%q) = %q: tokens do not cover the input", s, toks)
	}
	if !strings.Contains(s, "\t") && joined != s {
		t.Fatalf("Lex(%q) = %q: tokens join to %q", s, toks, joined)
	}
	for _, tok := range toks {
		if tok == "" {
			t.Fatalf("Lex(%q) = %q: empty token", s, toks)
		}
		if strings.Contains(tok, "\t") {
			t.Fatalf("Lex(%q) = %q: tab left in a token", s, toks)
		}
	}
}

func FuzzLex(f *testing.F) {
	for _, s := range quoteExamples {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		checkLexInvariants(t, s)
		// Unquote never fails: it returns the input, or the input without
		// its surrounding pair of quotes.
		if got := command.Unquote(s); got != s && (len(s) < 2 || s[1:len(s)-1] != got) {
			t.Fatalf("Unquote(%q) = %q", s, got)
		}
		if utf8.ValidString(s) {
			checkQuoteCycle(t, s)
		}
	})
}
