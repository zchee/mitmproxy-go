// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package filter

import (
	json "encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

// golden is what testdata/parse_oracle.py records from the pinned upstream
// mitmproxy for every expression in testdata/parse_corpus.json.
type golden struct {
	Help    [][2]string    `json:"help"`
	Records []goldenRecord `json:"records"`
}

type goldenRecord struct {
	Expr                  string `json:"expr"`
	OK                    bool   `json:"ok"`
	Tree                  any    `json:"tree,omitzero"`
	Describe              string `json:"describe,omitzero"`
	DescribeCaseSensitive string `json:"describe_case_sensitive,omitzero"`
	Dump                  string `json:"dump,omitzero"`
}

func loadJSON(t testing.TB, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

func loadCorpus(t testing.TB) []string {
	t.Helper()
	var corpus []string
	loadJSON(t, "parse_corpus.json", &corpus)
	return corpus
}

func loadGolden(t testing.TB) golden {
	t.Helper()
	var g golden
	loadJSON(t, "parse_golden.json", &g)
	return g
}

// tree renders e in the shape parse_oracle.py uses: the upstream class
// name followed by the argument or the children.
func tree(e Expr) any {
	switch e := e.(type) {
	case *Unary:
		return []any{tokens[e.Token].class}
	case *Rex:
		return []any{tokens[e.Token].class, e.Pattern}
	case *Int:
		return []any{tokens[e.Token].class, e.Value}
	case *And:
		return append([]any{"FAnd"}, trees(e.Exprs)...)
	case *Or:
		return append([]any{"FOr"}, trees(e.Exprs)...)
	case *Not:
		return []any{"FNot", tree(e.Expr)}
	}
	return []any{"unknown"}
}

func trees(es []Expr) []any {
	out := make([]any, len(es))
	for i, e := range es {
		out[i] = tree(e)
	}
	return out
}

func dumpString(t testing.TB, e Expr) string {
	t.Helper()
	var b strings.Builder
	if err := Dump(&b, e); err != nil {
		t.Fatalf("Dump(%v) error = %v", e, err)
	}
	return b.String()
}

// TestParseMatchesUpstream checks that Parse accepts exactly the corpus
// expressions upstream accepts, builds the same tree, and renders it the
// same way through Describe and Dump.
func TestParseMatchesUpstream(t *testing.T) {
	corpus := loadCorpus(t)
	g := loadGolden(t)
	if len(g.Records) != len(corpus) {
		t.Fatalf("golden has %d records for %d corpus expressions; regenerate it with testdata/parse_oracle.py", len(g.Records), len(corpus))
	}
	for i, rec := range g.Records {
		if rec.Expr != corpus[i] {
			t.Fatalf("golden record %d is for %q, corpus has %q; regenerate it", i, rec.Expr, corpus[i])
		}
		name := rec.Expr
		if len(name) > 60 {
			name = name[:60] + "..."
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("MITMPROXY_CASE_SENSITIVE_FILTERS", "")
			e, err := Parse(rec.Expr)
			if !rec.OK {
				if err == nil {
					t.Fatalf("Parse(%q) = %s, upstream rejects it", rec.Expr, tree(e))
				}
				if err.Error() == "" {
					t.Errorf("Parse(%q) returned an empty error message", rec.Expr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) error = %v, upstream accepts it as %v", rec.Expr, err, rec.Tree)
			}
			if diff := gocmp.Diff(rec.Tree, tree(e)); diff != "" {
				t.Errorf("Parse(%q) tree mismatch (-upstream +go):\n%s", rec.Expr, diff)
			}
			if got := e.Describe(); got != rec.Describe {
				t.Errorf("Describe() = %q, upstream str() = %q", got, rec.Describe)
			}
			if got := dumpString(t, e); got != rec.Dump {
				t.Errorf("Dump() = %q, upstream dump() = %q", got, rec.Dump)
			}

			t.Setenv("MITMPROXY_CASE_SENSITIVE_FILTERS", "1")
			cs, err := Parse(rec.Expr)
			if err != nil {
				t.Fatalf("case-sensitive Parse(%q) error = %v", rec.Expr, err)
			}
			if got := cs.Describe(); got != rec.DescribeCaseSensitive {
				t.Errorf("case-sensitive Describe() = %q, upstream str() = %q", got, rec.DescribeCaseSensitive)
			}
		})
	}
}

// TestRoundTrip checks that String renders every accepted corpus expression
// in a form that parses back to the same tree and is a fixed point.
func TestRoundTrip(t *testing.T) {
	for _, expr := range loadCorpus(t) {
		e, err := Parse(expr)
		if err != nil {
			continue
		}
		s := e.String()
		again, err := Parse(s)
		if err != nil {
			t.Errorf("Parse(%q) = %q, which does not parse: %v", expr, s, err)
			continue
		}
		if diff := gocmp.Diff(tree(e), tree(again)); diff != "" {
			t.Errorf("Parse(%q).String() = %q parses to a different tree (-first +second):\n%s", expr, s, diff)
		}
		if s2 := again.String(); s2 != s {
			t.Errorf("String() is not a fixed point for %q: %q then %q", expr, s, s2)
		}
	}
}

func TestHelpMatchesUpstream(t *testing.T) {
	g := loadGolden(t)
	got := make([][2]string, 0, len(g.Help))
	for _, h := range Help() {
		got = append(got, [2]string{h.Expr, h.Help})
	}
	if diff := gocmp.Diff(g.Help, got); diff != "" {
		t.Errorf("Help() mismatch (-upstream +go):\n%s", diff)
	}
}
