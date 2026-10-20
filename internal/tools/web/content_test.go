// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"context"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
)

func testContentLineLimits(t *testing.T) {
	tests := map[string]struct {
		value, path, text string
		status            int
		emptyMessages     bool
	}{
		"one":                       {value: "1", status: 200, text: "foo\n"},
		"zero":                      {value: "0", status: 200, text: "foo\nbar"},
		"negative":                  {value: "-1", status: 500},
		"malformed":                 {value: "not-a-number", status: 500},
		"float":                     {value: "1.0", status: 500},
		"huge_positive":             {value: "9223372036854775808", status: 200, text: "foo\nbar"},
		"huge_negative":             {value: "-9223372036854775809", status: 500},
		"underscores":               {value: "1_000", status: 200, text: "foo\nbar"},
		"unicode_digits":            {value: "１２", status: 500},
		"explicit_plus":             {value: "+2", status: 200, text: "foo\nbar"},
		"whitespace":                {value: " 1 ", status: 200, text: "foo\n"},
		"maximum_decimal_digits":    {value: strings.Repeat("9", 4300), status: 200, text: "foo\nbar"},
		"over_decimal_digits":       {value: strings.Repeat("9", 4301), status: 500},
		"over_zero_digits":          {value: strings.Repeat("0", 4301), status: 500},
		"bad_underscore":            {value: "1__0", status: 500},
		"unicode_whitespace":        {value: "　1　", status: 500},
		"negative_empty_messages":   {value: "-1", path: "/flows/43/messages/content/raw", status: 200, emptyMessages: true},
		"negative_missing_messages": {value: "-1", path: "/flows/42/messages/content/raw", status: 400},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			h := newRouteHarness(t)
			path := test.path
			if path == "" {
				path = "/flows/42/request/content/raw"
			}
			if test.emptyMessages {
				h.do(t, func(context.Context) error {
					h.app.view.GetByID("43").(*flow.HTTPFlow).WebSocket.Messages = nil
					return nil
				})
			}
			response, body := h.fetch(t, http.MethodGet, path+"?lines="+url.QueryEscape(test.value), nil, "")
			if response.StatusCode != test.status {
				t.Fatalf("status=%d want=%d body=%q", response.StatusCode, test.status, body)
			}
			if test.status == 500 {
				want := "<html><title>500: Internal Server Error</title><body>500: Internal Server Error</body></html>"
				if diff := gocmp.Diff(want, string(body)); diff != "" {
					t.Fatal(diff)
				}
				return
			}
			if test.status != 200 {
				return
			}
			if test.emptyMessages {
				if diff := gocmp.Diff("[]", string(body)); diff != "" {
					t.Fatal(diff)
				}
				return
			}
			var value map[string]any
			if err := json.Unmarshal(body, &value); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.text, value["text"]); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func testFirstRequestArgument(t *testing.T) {
	tests := map[string]struct {
		query string
		body  url.Values
		want  string
		found bool
	}{
		"query_before_body": {query: "?lines=2&lines=1", body: url.Values{"lines": {"3", "4"}}, want: "2", found: true},
		"first_body_value":  {body: url.Values{"lines": {"3", "4"}}, want: "3", found: true},
		"empty_query_value": {query: "?lines=", body: url.Values{"lines": {"3"}}, want: "", found: true},
		"missing":           {},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequestWithContext(t.Context(), "GET", "/"+test.query, nil)
			request.PostForm = test.body
			value, found := firstRequestArgument(request, "lines")
			if value != test.want || found != test.found {
				t.Fatalf("argument=(%q,%v) want=(%q,%v)", value, found, test.want, test.found)
			}
		})
	}
}
