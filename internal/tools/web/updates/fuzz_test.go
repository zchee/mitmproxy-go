// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package updates

import (
	"testing"

	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func FuzzWebUpdateMessage(f *testing.F) {
	for _, seed := range []string{
		`{"type":"flows/updateFilter","payload":{"name":"search","expr":"~bq foo"}}`,
		`{"type":"flows/updateFilter","payload":{"name":"search","expr":""}}`,
		`{"type":"flows/updateFilter"}`, `{"type":"unknownCommand"}`, `invalid json`,
		`null`, `[]`, `{"type":"unknown","type":"flows/updateFilter","payload":{"name":"雪","expr":"~m GET"}}`,
		`{"type":"flows/updateFilter","payload":{"name":null,"expr":null}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		name, expression, err := parseCommand(body)
		if len(body) > messageLimit && err == nil {
			t.Fatal("oversized command accepted")
		}
		if err == nil && len(name)+len(expression) > len(body) {
			t.Fatal("decoded command grew beyond its source")
		}
	})
}

func FuzzWebUpdateFilter(f *testing.F) {
	for _, seed := range []string{"", "~bq foo", "~m GET", "~u example", "[", "~not-a-filter", "雪", "(~m GET | ~m POST) & !~e"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, expression string) {
		if len(expression) > messageLimit {
			return
		}
		parsed, err := filter.Parse(expression)
		if err != nil {
			return
		}
		item := testflow.TFlow(testflow.WithResponse)
		item.Request.SetContent([]byte("foo"))
		_ = filter.Match(parsed, item)
	})
}
