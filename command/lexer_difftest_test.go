// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package command_test

import (
	"bufio"
	"bytes"
	json "encoding/json/v2"
	rand "math/rand/v2"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/internal/difftest"
)

// pythonLexScript reads one JSON string per line and prints, per line, a
// JSON object with the tokens of mitmproxy's command lexer, quote and
// unquote of the input, and str.isspace of each token, which parse_partial
// uses to tell separators from arguments.
const pythonLexScript = `
import json, sys
from mitmproxy import command_lexer

for line in sys.stdin:
    s = json.loads(line)
    toks = list(command_lexer.expr.parse_string(s, parse_all=True))
    print(json.dumps({
        "tokens": toks,
        "space": [t.isspace() for t in toks],
        "quote": command_lexer.quote(s),
        "unquote": command_lexer.unquote(s),
    }))
`

// lexResult is one line of pythonLexScript's output.
type lexResult struct {
	Tokens  []string `json:"tokens"`
	Space   []bool   `json:"space"`
	Quote   string   `json:"quote"`
	Unquote string   `json:"unquote"`
}

// lexCorpus returns hand-picked command lines followed by random ones drawn
// from a pool weighted towards quotes, separators, tabs and whitespace that
// is not a separator.
func lexCorpus() []string {
	corpus := []string{
		"", " ", "a", "set foo bar", `set foo "bar baz"`, `set foo 'bar baz'`,
		`"unterminated`, `'unterminated`, `"a 'b' c"`, `'a "b" c'`, `a"b"c`,
		`flow.kill @all`, `flow.set @focus url "http://example.com/a b"`,
		"\t", "a\tb", "abcdefgh\tx", "'\t'", "a\n\tb", "a\r\tb", "\U000000e9\t.",
		"\v", "a\vb", "\f", "\x1c", "a \x1f b", "\u0085", "\U000000a0", "\U00003000",
		"\U00002028", `\x22`, `"a\x22b"`, `\`, `"\`, `''`, `""`, `"'`,
		"  leading", "trailing  ", "\r\n", "x\r\ny",
	}
	pool := []string{
		"a", "b", "z", ".", "@", "~", "-", "=", "\\", "\"", "'", "\"", "'",
		" ", " ", " ", "\t", "\t", "\n", "\r", "\v", "\f", "\x1c", "\x1f",
		"\u0085", "\U000000a0", "\U00003000", "\U00002028", "\U000000e9", "\U0001f600",
	}
	rng := rand.New(rand.NewPCG(20261005, 1))
	for range 400 {
		var b strings.Builder
		for range rng.IntN(16) {
			b.WriteString(pool[rng.IntN(len(pool))])
		}
		corpus = append(corpus, b.String())
	}
	return corpus
}

// TestDifferentialLex lexes a corpus of command lines with mitmproxy's
// command_lexer and with Lex, and compares the tokens, which tokens are
// whitespace to Python, and Quote and Unquote.
func TestDifferentialLex(t *testing.T) {
	corpus := lexCorpus()
	var in bytes.Buffer
	for _, s := range corpus {
		line, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("json.Marshal(%q): %v", s, err)
		}
		in.Write(line)
		in.WriteByte('\n')
	}
	out := difftest.Python(t, pythonLexScript, in.Bytes())
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(nil, 1<<20)
	i := 0
	for ; sc.Scan(); i++ {
		if i >= len(corpus) {
			t.Fatalf("Python printed more than %d lines", len(corpus))
		}
		s := corpus[i]
		var want lexResult
		if err := json.Unmarshal(sc.Bytes(), &want); err != nil {
			t.Fatalf("line %d %q: %v", i, sc.Text(), err)
		}
		toks := command.Lex(s)
		got := lexResult{
			Tokens:  toks,
			Space:   make([]bool, len(toks)),
			Quote:   command.Quote(s),
			Unquote: command.Unquote(s),
		}
		for j, tok := range toks {
			got.Space[j] = command.IsSpaceToken(tok)
		}
		if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("command line %q (-python +go):\n%s", s, diff)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if i != len(corpus) {
		t.Fatalf("Python printed %d lines for %d command lines", i, len(corpus))
	}
}
