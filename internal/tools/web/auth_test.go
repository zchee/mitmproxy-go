// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/flow"
)

func testWebLoginPost(t *testing.T) {
	tests := map[string]struct {
		token   string
		status  int
		heading string
	}{
		"valid":   {token: "route-test", status: 200},
		"invalid": {token: "wrong", status: 403, heading: "403 Invalid Password"},
		"empty":   {status: 403, heading: "403 Authentication Required"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			h := newRouteHarness(t)
			form := url.Values{"token": {test.token}, "_xsrf": {h.xsrf}}
			request, err := http.NewRequestWithContext(t.Context(), "POST", h.server.URL+"/", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response, err := h.server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil {
				t.Fatalf("login response read=%v close=%v", readErr, closeErr)
			}
			if response.StatusCode != test.status {
				t.Fatalf("login status=%d want=%d", response.StatusCode, test.status)
			}
			if test.heading != "" && !strings.Contains(string(body), test.heading) {
				t.Fatal("login failure heading missing")
			}
			if test.status == 200 {
				expected, err := assets.ReadFile("index.html")
				if err != nil {
					t.Fatal(err)
				}
				if string(body) != string(expected) {
					t.Fatal("successful form login did not render the embedded index")
				}
				request, err := http.NewRequestWithContext(t.Context(), "GET", h.server.URL+"/flows", nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := h.server.Client().Do(request)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = response.Body.Close() }()
				if response.StatusCode != 200 {
					t.Fatal("successful form login did not establish a reusable session")
				}
			}
		})
	}
}

func testWebAuthPolicy(t *testing.T) {
	tests := map[string]struct {
		method, path, authorization, xsrf, site string
		session                                 bool
		status                                  int
	}{
		"bearer":                           {method: "GET", path: "/flows", authorization: "Bearer route-test", status: 200},
		"session_cookie":                   {method: "PUT", path: "/flows/42", session: true, xsrf: "valid", status: 200},
		"missing_xsrf":                     {method: "PUT", path: "/flows/42", authorization: "Bearer route-test", status: 403},
		"mismatched_xsrf":                  {method: "PUT", path: "/flows/42", authorization: "Bearer route-test", xsrf: "wrong", status: 403},
		"cross_site":                       {method: "PUT", path: "/flows/42", authorization: "Bearer route-test", xsrf: "valid", site: "cross-site", status: 403},
		"same_site":                        {method: "PUT", path: "/flows/42", authorization: "Bearer route-test", xsrf: "valid", site: "same-site", status: 403},
		"same_origin":                      {method: "PUT", path: "/flows/42", authorization: "Bearer route-test", xsrf: "valid", site: "same-origin", status: 200},
		"bad_bearer_blocks_query_fallback": {method: "GET", path: "/flows?token=route-test", authorization: "Bearer wrong", status: 403},
		"static_is_public":                 {method: "GET", path: "/static/index-Be7e-cwP.js", status: 200},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			h := newRouteHarness(t)
			if test.session {
				h.status(t, "GET", "/", nil, "", 200)
			}
			request, err := http.NewRequestWithContext(t.Context(), test.method, h.server.URL+test.path, strings.NewReader(`{"comment":"policy update"}`))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			if test.authorization != "" {
				request.Header.Set("Authorization", test.authorization)
			}
			if test.xsrf != "" {
				value := test.xsrf
				if value == "valid" {
					value = h.xsrf
				}
				request.Header.Set("X-XSRFToken", value)
			}
			if test.site != "" {
				request.Header.Set("Sec-Fetch-Site", test.site)
			}
			response, err := h.server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			if _, err := io.Copy(io.Discard, response.Body); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != test.status {
				t.Fatalf("policy status=%d want=%d", response.StatusCode, test.status)
			}
			h.do(t, func(context.Context) error {
				want := ""
				if test.method == http.MethodPut && test.status == 200 {
					want = "policy update"
				}
				if got := h.app.view.GetByID("42").(*flow.HTTPFlow).Comment; got != want {
					t.Fatalf("policy mutation=%q want=%q", got, want)
				}
				return nil
			})
		})
	}
}
