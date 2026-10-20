// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/master"
)

func TestWebRouteMethods(t *testing.T) {
	t.Run("manifest", func(t *testing.T) {
		tests := map[string]struct {
			path    string
			methods map[string]string
			alias   bool
			shape   string
		}{
			"index":             {path: "/", methods: map[string]string{"GET": "", "POST": ""}, shape: "html"},
			"filter_help":       {path: "/filter-help", methods: map[string]string{"GET": ""}, alias: true, shape: "object"},
			"commands":          {path: "/commands", methods: map[string]string{"GET": ""}, alias: true, shape: "object"},
			"command_execute":   {path: "/commands/commands.history.get", methods: map[string]string{"POST": `{"arguments":[]}`}, shape: "object"},
			"events":            {path: "/events", methods: map[string]string{"GET": ""}, alias: true, shape: "array"},
			"flows":             {path: "/flows", methods: map[string]string{"GET": ""}, alias: true, shape: "array"},
			"flows_resume":      {path: "/flows/resume", methods: map[string]string{"POST": ""}},
			"flows_kill":        {path: "/flows/kill", methods: map[string]string{"POST": ""}},
			"flow":              {path: "/flows/42", methods: map[string]string{"PUT": `{"comment":"updated"}`, "DELETE": ""}},
			"flow_resume":       {path: "/flows/42/resume", methods: map[string]string{"POST": ""}},
			"flow_kill":         {path: "/flows/42/kill", methods: map[string]string{"POST": ""}},
			"flow_duplicate":    {path: "/flows/42/duplicate", methods: map[string]string{"POST": ""}, shape: "id"},
			"flow_replay":       {path: "/flows/42/replay", methods: map[string]string{"POST": ""}},
			"flow_revert":       {path: "/flows/42/revert", methods: map[string]string{"POST": ""}},
			"flow_content_view": {path: "/flows/42/request/content/raw", methods: map[string]string{"GET": ""}, alias: true, shape: "object"},
			"clear":             {path: "/clear", methods: map[string]string{"POST": ""}},
			"options":           {path: "/options", methods: map[string]string{"GET": "", "PUT": `{"anticache":true}`}, alias: true, shape: "object"},
			"options_save":      {path: "/options/save", methods: map[string]string{"POST": ""}},
			"processes":         {path: "/processes", methods: map[string]string{"GET": ""}, shape: "array"},
			"executable_icon":   {path: "/executable-icon?path=invalid", methods: map[string]string{"GET": ""}, shape: "png"},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				h := newRouteHarness(t)
				paths := []string{test.path}
				if test.alias {
					paths = append(paths, test.path+".json")
				}
				for _, path := range paths {
					for _, method := range []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"} {
						input, supported := test.methods[method]
						if !supported {
							response, body := h.fetch(t, method, path, nil, "")
							want := "<html><title>405: Method Not Allowed</title><body>405: Method Not Allowed</body></html>"
							if method == "HEAD" {
								want = ""
							}
							if response.StatusCode != 405 || response.ContentLength != 87 || string(body) != want || response.Header.Get("Content-Type") != "text/html; charset=UTF-8" {
								t.Fatalf("%s %s unsupported: status=%d headers=%v body=%q", method, path, response.StatusCode, response.Header, body)
							}
							continue
						}
						if name == "flow_replay" {
							testWebReplay(t, h)
							continue
						}
						response, body := h.fetch(t, method, path, []byte(input), "application/json")
						if response.StatusCode != 200 {
							t.Fatalf("%s %s: status=%d body=%q", method, path, response.StatusCode, body)
						}
						shape := test.shape
						if method != "GET" && name != "command_execute" && name != "flow_duplicate" && name != "index" {
							shape = ""
						}
						switch shape {
						case "object", "array":
							var value any
							if err := json.Unmarshal(body, &value); err != nil {
								t.Fatalf("invalid JSON %q: %v", body, err)
							}
							if shape == "object" {
								if _, ok := value.(map[string]any); !ok {
									t.Fatalf("object response=%T", value)
								}
							} else if _, ok := value.([]any); !ok {
								t.Fatalf("array response=%T", value)
							}
							if response.Header.Get("Content-Type") != "application/json; charset=UTF-8" {
								t.Fatal(response.Header)
							}
						case "html":
							if !bytes.Contains(body, []byte("<html")) || response.Header.Get("Content-Type") != "text/html; charset=UTF-8" {
								t.Fatalf("HTML response=%q", body)
							}
						case "id":
							if strings.ContainsAny(string(body), "\"{}\n") || len(body) == 0 {
								t.Fatalf("duplicate body=%q", body)
							}
						case "png":
							if !bytes.Equal(body, transparentPNG) || response.Header.Get("Content-Type") != "image/png" || response.Header.Get("Cache-Control") != "max-age=604800" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
								t.Fatalf("PNG headers=%v body=%x", response.Header, body)
							}
						default:
							if len(body) != 0 {
								t.Fatalf("empty response=%q", body)
							}
						}
					}
				}
				if name == "options_save" {
					entries, err := os.ReadDir(h.app.master.Options.Str("confdir"))
					if err != nil {
						t.Fatal(err)
					}
					for _, entry := range entries {
						if entry.Name() == "config.yaml" {
							t.Fatal("options/save wrote config.yaml")
						}
					}
				}
				if name == "flow_content_view" {
					h.do(t, func(ctx context.Context) error {
						tcp := testflow.TTCPFlow()
						tcp.ID = "51"
						udp := testflow.TUDPFlow()
						udp.ID = "52"
						h.app.view.Add(ctx, []flow.Flow{tcp, udp})
						return nil
					})
					for _, path := range []string{"/flows/42/response/content/raw", "/flows/51/messages/content/raw?lines=1", "/flows/52/messages/content/raw?lines=1", "/flows/43/messages/content/raw?lines=1"} {
						h.status(t, "GET", path, nil, "", 200)
					}
					h.status(t, "GET", "/flows/42/messages/content/raw", nil, "", 400)
				}
			})
		}
	})
	t.Run("diagnostics", func(t *testing.T) {
		tests := map[string]struct {
			path, body, contentType string
			status                  int
			prefix                  string
		}{
			"content_type":             {path: "/flows/42", body: "{}", status: 400, prefix: "Invalid Content-Type, expected application/json."},
			"json_invalid_character":   {path: "/flows/42", body: "!!", contentType: "application/json", status: 400, prefix: "Malformed JSON:"},
			"json_truncated":           {path: "/flows/42", body: `{"comment":`, contentType: "application/json", status: 400, prefix: "Malformed JSON:"},
			"unknown_top_field":        {path: "/flows/42", body: `{"unknown":{"a":true,"b":[null,"x"]}}`, contentType: "application/json", status: 400, prefix: "Unknown update unknown: {'a': True, 'b': [None, 'x']}"},
			"unknown_request_field":    {path: "/flows/42", body: `{"request":{"foo":42}}`, contentType: "application/json", status: 400, prefix: "Unknown update request.foo: 42"},
			"unknown_response_field":   {path: "/flows/42", body: `{"response":{"status_code":42}}`, contentType: "application/json", status: 400, prefix: "Unknown update response.status_code: 42"},
			"wrong_flow_edit_type":     {path: "/flows/42", body: `[]`, contentType: "application/json", status: 500, prefix: "<html><title>500:"},
			"wrong_option_update_type": {path: "/options", body: `[]`, contentType: "application/json", status: 400, prefix: "JSON value has kind"},
			"missing_before_json":      {path: "/flows/1234", body: "!!", contentType: "application/json", status: 404, prefix: "Flow not found."},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				h := newRouteHarness(t)
				body := h.status(t, "PUT", test.path, []byte(test.body), test.contentType, test.status)
				if !strings.HasPrefix(string(body), test.prefix) {
					t.Fatalf("error=%q want prefix=%q", body, test.prefix)
				}
				if strings.HasPrefix(name, "json_") && !bytes.Contains(body, []byte("(byte ")) {
					t.Fatalf("JSON error lost parser location: %q", body)
				}
			})
		}
	})
	t.Run("regex_and_missing", func(t *testing.T) {
		tests := map[string]struct {
			method, path string
			status       int
			body         string
		}{
			"unknown":            {method: "GET", path: "/missing", status: 404},
			"unknown_alias":      {method: "GET", path: "/flows/42.json", status: 404},
			"uppercase_id":       {method: "DELETE", path: "/flows/ABC", status: 404},
			"id_slash":           {method: "DELETE", path: "/flows/42%2fkill", status: 405},
			"command_underscore": {method: "POST", path: "/commands/not_allowed", status: 404},
			"command_digit":      {method: "POST", path: "/commands/foo2", status: 404},
			"view_dot":           {method: "GET", path: "/flows/42/request/content/raw.extra", status: 404},
			"noncanonical":       {method: "GET", path: "/flows//42", status: 404},
			"missing_flow":       {method: "POST", path: "/flows/1234/resume", status: 404, body: "Flow not found."},
			"flow_get":           {method: "GET", path: "/flows/42", status: 405},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				h := newRouteHarness(t)
				response, body := h.fetch(t, test.method, test.path, nil, "")
				want := test.body
				if want == "" {
					want = fmt.Sprintf("<html><title>%d: %s</title><body>%d: %s</body></html>", test.status, http.StatusText(test.status), test.status, http.StatusText(test.status))
				}
				if response.StatusCode != test.status || string(body) != want {
					t.Fatalf("status=%d body=%q want %d %q", response.StatusCode, body, test.status, want)
				}
			})
		}
	})
}

func TestWebRouteAuth(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		t.Run("test_all_handlers_have_auth", func(t *testing.T) {
			h := newRouteHarness(t)
			for _, route := range webRoutes {
				if route.pattern == nil || route.methods == "" || h.app.protect == nil {
					t.Fatalf("route lacks authentication boundary: %s", route.name)
				}
			}
		})
	})
	tests := map[string]struct{ method, path string }{"index": {"GET", "/"}, "flows": {"GET", "/flows"}, "commands": {"GET", "/commands"}, "options": {"PUT", "/options"}, "kill": {"POST", "/flows/42/kill"}, "icon": {"GET", "/executable-icon?path=invalid"}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			h := newRouteHarness(t)
			request, err := http.NewRequestWithContext(t.Context(), test.method, h.server.URL+test.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := h.server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != 403 {
				t.Fatalf("unauthenticated status=%d", response.StatusCode)
			}
		})
	}
}

type dispatchWriteCheck struct {
	*httptest.ResponseRecorder
	master      *master.Master
	ctx         context.Context
	beforeWrite func(context.Context) error
}

func (w dispatchWriteCheck) Write(body []byte) (int, error) {
	if err := w.master.Do(w.ctx, w.beforeWrite); err != nil {
		return 0, err
	}
	return w.ResponseRecorder.Write(body)
}

func TestWebMutationDispatch(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"response_outside_dispatch": {func(t *testing.T) {
			h := newRouteHarness(t)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			response := dispatchWriteCheck{ResponseRecorder: httptest.NewRecorder(), master: h.app.master, ctx: ctx, beforeWrite: func(context.Context) error {
				h.app.view.GetByID("42").Common().Comment = "changed after snapshot"
				return nil
			}}
			request := httptest.NewRequestWithContext(ctx, "GET", "/flows", nil)
			if err := h.app.serve(response, request, "flows", nil); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(response.Body.Bytes(), []byte("changed after snapshot")) {
				t.Fatal("response retained live flow state")
			}
			if got := h.status(t, "GET", "/flows", nil, "", 200); !bytes.Contains(got, []byte("changed after snapshot")) {
				t.Fatal("response writer never entered dispatch")
			}
		}},
		"rollback_and_header_order": {func(t *testing.T) {
			h := newRouteHarness(t)
			h.put(t, "/flows/42", `{"request":{"headers":[["X-Duplicate","a"],["x-duplicate","b"]],"trailers":[["T","a"],["T","b"]]}}`, 200)
			h.do(t, func(context.Context) error {
				f := h.app.view.GetByID("42").(*flow.HTTPFlow)
				if diff := gocmp.Diff([]string{"a", "b"}, f.Request.Headers.GetAll("x-duplicate")); diff != "" {
					t.Fatal(diff)
				}
				if diff := gocmp.Diff([]string{"a", "b"}, f.Request.Trailers.GetAll("t")); diff != "" {
					t.Fatal(diff)
				}
				return nil
			})
			h.put(t, "/flows/42", `{"comment":"do not keep","request":{"unknown":42}}`, 400)
			h.do(t, func(context.Context) error {
				f := h.app.view.GetByID("42")
				if f.Common().Comment != "" || f.Modified() {
					t.Fatal("failed edit was not reverted to backup")
				}
				return nil
			})
		}},
		"raw_dump_roundtrip": {func(t *testing.T) {
			h := newRouteHarness(t)
			body := h.status(t, "GET", "/flows/dump", nil, "", 200)
			h.status(t, "POST", "/flows/dump", body, "application/octet-stream", 200)
			h.do(t, func(context.Context) error {
				if h.app.view.Len() != 3 {
					t.Fatalf("dump roundtrip flow count=%d", h.app.view.Len())
				}
				for _, id := range []string{"42", "43", "44"} {
					if h.app.view.GetByID(id) == nil {
						t.Fatalf("dump lost flow %s", id)
					}
				}
				return nil
			})
		}},
		"real_replay": {func(t *testing.T) { testWebReplay(t, newRouteHarness(t)) }},
		"clear_order": {func(t *testing.T) {
			h := newRouteHarness(t)
			h.status(t, "POST", "/clear", nil, "", 200)
			if body := h.status(t, "GET", "/flows", nil, "", 200); string(body) != "[]" {
				t.Fatalf("flows=%q", body)
			}
			if body := h.status(t, "GET", "/events", nil, "", 200); string(body) != "[]" {
				t.Fatalf("events=%q", body)
			}
		}},
	}
	for name, test := range tests {
		t.Run(name, test.run)
	}
}
