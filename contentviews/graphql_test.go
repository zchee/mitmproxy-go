// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGraphQL(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]func(*testing.T){
			"test_render_priority": func(t *testing.T) {
				tests := map[string]struct {
					data     string
					media    string
					priority float64
				}{
					"object":     {`{"query": "query P { \n }"}`, "application/json", 2},
					"batch":      {`[{"query": "query P { \n }"}]`, "application/json", 2},
					"wrong MIME": {`[{"query": "query P { \n }"}]`, "text/html", 0},
					"xquery":     {`[{"xquery": "query P { \n }"}]`, "application/json", 0},
					"empty":      {`[]`, "application/json", 0},
					"malformed":  {`}`, "application/json", 0},
				}
				for name, tt := range tests {
					if got := (GraphQL{}).RenderPriority([]byte(tt.data), Metadata{ContentType: tt.media}); got != tt.priority {
						t.Errorf("%s: priority=%v want=%v", name, got, tt.priority)
					}
				}
			},
			"test_format_graphql": func(t *testing.T) {
				budget := newViewBudget("GraphQL")
				node, err := parseGraphQLJSON([]byte(`{"query": "query P { \\n }"}`), budget)
				if err != nil {
					t.Fatal(err)
				}
				var out strings.Builder
				if err := formatGraphQL(&out, node, budget); err != nil || out.Len() == 0 {
					t.Fatalf("format query failed: %v", err)
				}
			},
			"test_format_query_list": func(t *testing.T) {
				text, err := (GraphQL{}).Prettify([]byte(`[{"query": "query P { \\n }"}]`), Metadata{})
				if err != nil || !strings.HasPrefix(text, "--- 0/0\n") {
					t.Fatalf("format batch failed: %q %v", text, err)
				}
			},
			"test_view_graphql": func(t *testing.T) {
				const want = "{\n  \"query\": \"...\"\n}\n---\nquery P { \n }\n"
				text, err := (GraphQL{}).Prettify([]byte(`{"query": "query P { \n }"}`), Metadata{})
				if err != nil || text != want {
					t.Fatalf("object=%q, %v; want %q", text, err, want)
				}
				text, err = (GraphQL{}).Prettify([]byte(`[{"query": "query P { \n }"}]`), Metadata{})
				if err != nil || text != "--- 0/0\n"+want {
					t.Fatalf("batch=%q, %v", text, err)
				}
				if _, err := (GraphQL{}).Prettify([]byte(`"valid json"`), Metadata{}); err == nil {
					t.Fatal("non-GraphQL value accepted")
				}
			},
		}
		for name, test := range tests {
			t.Run(name, test)
		}
	})
}

func TestGraphQLAdditional(t *testing.T) {
	tests := map[string]struct {
		data string
		want string
	}{
		"ASCII envelope": {
			`{"query":"{\n 日本語 }","variables":{"word":"日本語","emoji":"😀","f":1e0}}`,
			"{\n  \"query\": \"...\",\n  \"variables\": {\n    \"word\": \"\\u65e5\\u672c\\u8a9e\",\n    \"emoji\": \"\\ud83d\\ude00\",\n    \"f\": 1.0\n  }\n}\n---\n{\n 日本語 }\n",
		},
		"duplicate query": {
			`{"query":"old","variables":null,"query":"new\nquery"}`,
			"{\n  \"query\": \"...\",\n  \"variables\": null\n}\n---\nnew\nquery\n",
		},
		"special floats": {
			`{"query":"{\n}","variables":[NaN,Infinity,-Infinity]}`,
			"{\n  \"query\": \"...\",\n  \"variables\": [\n    NaN,\n    Infinity,\n    -Infinity\n  ]\n}\n---\n{\n}\n",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := (GraphQL{}).Prettify([]byte(tt.data), Metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	budget := newViewBudget("GraphQL")
	budget.output = budget.limits.OutputBytes - 1
	var out strings.Builder
	if err := graphQuote(&out, budget, "é"); err == nil {
		t.Fatal("escaped Unicode bypassed output limit")
	} else if _, ok := errors.AsType[*LimitError](err); !ok {
		t.Fatalf("expected typed output limit, got %v", err)
	}
	// An object member costs two nodes, its key and its value, charged
	// together before the key is read: a member the node budget cannot hold
	// is refused at the key, with the counter left where the last whole
	// member ended, so its key is never decoded.
	t.Run("node budget refuses a member before its key is read", func(t *testing.T) {
		tests := map[string]struct {
			data      string
			nodes     uint64
			wantNodes uint64
		}{
			"error: second member does not fit": {
				data:      `{"query":"q","b":1}`,
				nodes:     4,
				wantNodes: 3,
			},
			"error: many keys stop at the last whole member": {
				data:      "{" + strings.Repeat(`"k":0,`, 999) + `"k":0}`,
				nodes:     1000,
				wantNodes: 999,
			},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				budget := newViewBudget("GraphQL")
				budget.limits.Nodes = tt.nodes
				_, err := parseGraphQLJSON([]byte(tt.data), budget)
				limit, ok := errors.AsType[*LimitError](err)
				if !ok {
					t.Fatalf("error %v is not a *LimitError", err)
				}
				if diff := cmp.Diff([]string{"JSON key", "logical nodes"}, []string{limit.Stage, limit.Resource}); diff != "" {
					t.Fatalf("refusal (-want +got):\n%s", diff)
				}
				if budget.nodes != tt.wantNodes {
					t.Fatalf("node counter = %d, want %d", budget.nodes, tt.wantNodes)
				}
			})
		}
		exact := newViewBudget("GraphQL")
		exact.limits.Nodes = 5
		if _, err := parseGraphQLJSON([]byte(`{"query":"q","b":1}`), exact); err != nil {
			t.Fatalf("an object that fits the node budget exactly: %v", err)
		}
	})
	depth := newViewBudget("GraphQL").limits.Depth
	deep := strings.Repeat("[", depth+1) + "0" + strings.Repeat("]", depth+1)
	if _, err := parseGraphQLJSON([]byte(deep), newViewBudget("GraphQL")); err == nil {
		t.Fatal("deep JSON accepted")
	}
}

func FuzzGraphQL(f *testing.F) {
	for _, seed := range []string{`{"query":"{\n}"}`, `[{"query":"query P { \\n }"}]`, `[]`, `}`, `{"query":null}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		text, err := (GraphQL{}).Prettify(data, Metadata{})
		if err == nil && uint64(len(text)) > newViewBudget("GraphQL").limits.OutputBytes {
			t.Fatal("output exceeds resource bound")
		}
	})
}
