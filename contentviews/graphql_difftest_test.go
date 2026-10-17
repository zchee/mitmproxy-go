// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package contentviews

import (
	json "encoding/json/v2"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestGraphQLDifferential(t *testing.T) {
	output := difftest.Python(t, `
import json
from mitmproxy.contentviews import Metadata
from mitmproxy.contentviews._view_graphql import format_graphql, format_query_list, graphql

single = b'{"query": "query P { \\n }"}'
batch = b'[{"query": "query P { \\n }"}]'
priorities = []
for data, media in [(single, "application/json"), (batch, "application/json"),
                    (batch, "text/html"), (b'[{"xquery":"query P { \\n }"}]', "application/json"),
                    (b'[]', "application/json"), (b'}', "application/json")]:
    priorities.append(graphql.render_priority(data, Metadata(content_type=media)))
result = {
    "priority": priorities,
    "format": format_graphql({"query": "query P { \\n }"}),
    "batch": format_query_list([{"query": "query P { \\n }"}]),
    "view": [graphql.prettify(single, Metadata()), graphql.prettify(batch, Metadata())],
}
try:
    graphql.prettify(b'"valid json"', Metadata())
    result["invalid_failed"] = False
except ValueError:
    result["invalid_failed"] = True
print(json.dumps(result))
`, nil)
	var reference struct {
		Priority      []float64 `json:"priority"`
		Format        string    `json:"format"`
		Batch         string    `json:"batch"`
		View          []string  `json:"view"`
		InvalidFailed bool      `json:"invalid_failed"`
	}
	if err := json.Unmarshal(output, &reference); err != nil {
		t.Fatal(err)
	}
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]func(*testing.T){
			"test_render_priority": func(t *testing.T) {
				inputs := []string{`{"query":"query P { \n }"}`, `[{"query":"query P { \n }"}]`, `[{"query":"query P { \n }"}]`, `[{"xquery":"query P { \n }"}]`, `[]`, `}`}
				var got []float64
				for i, input := range inputs {
					media := "application/json"
					if i == 2 {
						media = "text/html"
					}
					got = append(got, (GraphQL{}).RenderPriority([]byte(input), Metadata{ContentType: media}))
				}
				if diff := cmp.Diff(reference.Priority, got); diff != "" {
					t.Fatal(diff)
				}
			},
			"test_format_graphql": func(t *testing.T) {
				budget := newViewBudget("GraphQL")
				node, err := parseGraphQLJSON([]byte(`{"query":"query P { \\n }"}`), budget)
				if err != nil {
					t.Fatal(err)
				}
				var out strings.Builder
				if err := formatGraphQL(&out, node, budget); err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(reference.Format, out.String()); diff != "" {
					t.Fatal(diff)
				}
			},
			"test_format_query_list": func(t *testing.T) {
				got, err := (GraphQL{}).Prettify([]byte(`[{"query":"query P { \\n }"}]`), Metadata{})
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(reference.Batch, got); diff != "" {
					t.Fatal(diff)
				}
			},
			"test_view_graphql": func(t *testing.T) {
				var got []string
				for _, input := range []string{`{"query":"query P { \n }"}`, `[{"query":"query P { \n }"}]`} {
					text, err := (GraphQL{}).Prettify([]byte(input), Metadata{})
					if err != nil {
						t.Fatal(err)
					}
					got = append(got, text)
				}
				if diff := cmp.Diff(reference.View, got); diff != "" {
					t.Fatal(diff)
				}
				if _, err := (GraphQL{}).Prettify([]byte(`"valid json"`), Metadata{}); (err != nil) != reference.InvalidFailed {
					t.Fatalf("non-GraphQL error mismatch: %v", err)
				}
			},
		}
		for name, test := range tests {
			t.Run(name, test)
		}
	})
}
