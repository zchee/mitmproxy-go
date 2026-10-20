// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/anticache"
	"github.com/zchee/mitmproxy-go/addons/clientplayback"
	"github.com/zchee/mitmproxy-go/addons/commandhistory"
	"github.com/zchee/mitmproxy-go/addons/core"
	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/addons/proxyserver"
	"github.com/zchee/mitmproxy-go/addons/view"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/internal/tools/web/updates"
	"github.com/zchee/mitmproxy-go/internal/tools/web/webauth"
	"github.com/zchee/mitmproxy-go/master"
)

type routeHarness struct {
	app    *application
	server *httptest.Server
	xsrf   string
}

func newRouteHarness(t *testing.T, eventSize ...int) *routeHarness {
	t.Helper()
	m := master.New(master.Config{})
	confdir := t.TempDir()
	if err := m.Do(t.Context(), func(ctx context.Context) error { return m.Options.Update(ctx, map[string]any{"confdir": confdir}) }); err != nil {
		t.Fatal(err)
	}
	v := view.New(m.Addons)
	events, err := eventstore.New(eventSize...)
	if err != nil {
		t.Fatal(err)
	}
	app := &application{master: m, view: v, events: events}
	auth := webauth.New(m.Options)
	ps, err := proxyserver.New(proxy.Config{Manager: m.Addons, Options: m.Options, Connections: new(proxy.Connections)})
	if err != nil {
		t.Fatal(err)
	}
	app.proxyserver = ps
	if err := m.Addons.Add(t.Context(), core.New(m.Addons), anticache.New(m.Options), commandhistory.New(m.Options), clientplayback.New(m), ps, auth, v, events); err != nil {
		t.Fatal(err)
	}
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		return m.Options.Update(ctx, map[string]any{"web_password": "route-test"})
	}); err != nil {
		t.Fatal(err)
	}
	app.useAuth(auth)
	hub, err := updates.New(t.Context(), updates.Config{Master: m, View: v, Events: events, Servers: ps, Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	app.updates = hub
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		first := testflow.TFlow(testflow.WithResponse)
		first.ID = "42"
		first.Request.SetContent([]byte("foo\nbar"))
		second := testflow.TFlow(testflow.WithResponse, testflow.WithWebSocket)
		second.ID = "43"
		second.Request.RawContent = nil
		second.Response.RawContent = nil
		third := testflow.TFlow(testflow.WithError)
		third.ID = "44"
		v.Add(ctx, []flow.Flow{first, second, third})
		return events.Add(ctx, addon.LogEntry{Msg: "test log", Level: slog.LevelInfo})
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Addons.Trigger(t.Context(), addon.RunningHook{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Addons.Trigger(context.WithoutCancel(t.Context()), addon.DoneHook{}); err != nil {
			t.Error(err)
		}
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	server := httptest.NewServer(app.handler())
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	server.Client().Jar = jar
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read login response: %v; close: %v", readErr, closeErr)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthenticated login status=%d", response.StatusCode)
	}
	var xsrf string
	for _, cookie := range jar.Cookies(base) {
		if cookie.Name == "_mitmproxy_xsrf" {
			xsrf = cookie.Value
		}
	}
	if xsrf == "" {
		t.Fatal("real login middleware did not issue an XSRF cookie")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		if err := hub.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return &routeHarness{app: app, server: server, xsrf: xsrf}
}

func (h *routeHarness) do(t *testing.T, fn func(context.Context) error) {
	t.Helper()
	if err := h.app.master.Do(t.Context(), fn); err != nil {
		t.Fatal(err)
	}
}

func (h *routeHarness) fetch(t *testing.T, method, path string, body []byte, contentType string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, h.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer route-test")
	request.Header.Set("X-XSRFToken", h.xsrf)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := h.server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, data
}

func (h *routeHarness) status(t *testing.T, method, path string, body []byte, contentType string, want int) []byte {
	t.Helper()
	response, data := h.fetch(t, method, path, body, contentType)
	if response.StatusCode != want {
		t.Fatalf("%s %s: status=%d want=%d body=%q", method, path, response.StatusCode, want, data)
	}
	return data
}

func (h *routeHarness) put(t *testing.T, path, body string, want int) []byte {
	t.Helper()
	return h.status(t, "PUT", path, []byte(body), "application/json", want)
}

func TestWebRoutes(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]struct {
			run func(*testing.T, *routeHarness)
		}{
			"test_filter_help": {func(t *testing.T, h *routeHarness) { h.status(t, "GET", "/filter-help", nil, "", 200) }},
			"test_flows": {func(t *testing.T, h *routeHarness) {
				var values []map[string]any
				if err := json.Unmarshal(h.status(t, "GET", "/flows", nil, "", 200), &values); err != nil {
					t.Fatal(err)
				}
				if values[0]["request"].(map[string]any)["contentHash"] == nil || values[2]["error"] == nil {
					t.Fatalf("missing hash/error: %v", values)
				}
			}},
			"test_flows_dump": {func(t *testing.T, h *routeHarness) {
				if !bytes.Contains(h.status(t, "GET", "/flows/dump", nil, "", 200), []byte("address")) {
					t.Fatal("dump lacks address")
				}
			}},
			"test_flows_dump_filter": {func(t *testing.T, h *routeHarness) {
				if got := h.status(t, "GET", "/flows/dump?filter=foo", nil, "", 200); len(got) != 0 {
					t.Fatalf("filtered dump=%q", got)
				}
			}},
			"test_flows_dump_filter_error": {func(t *testing.T, h *routeHarness) { h.status(t, "GET", "/flows/dump?filter=[", nil, "", 400) }},
			"test_clear": {func(t *testing.T, h *routeHarness) {
				h.status(t, "POST", "/clear", nil, "", 200)
				h.do(t, func(context.Context) error {
					if h.app.view.Len() != 0 || len(h.app.events.Entries()) != 0 {
						t.Fatal("clear retained flows/events")
					}
					return nil
				})
			}},
			"test_resume": {func(t *testing.T, h *routeHarness) {
				h.do(t, func(context.Context) error {
					for _, f := range h.app.view.Flows() {
						f.Common().Intercept()
					}
					return nil
				})
				h.status(t, "POST", "/flows/42/resume", nil, "", 200)
				h.do(t, func(context.Context) error {
					if h.app.view.GetByID("42").Common().Intercepted() || !h.app.view.GetByID("43").Common().Intercepted() {
						t.Fatal("single resume changed wrong flows")
					}
					return nil
				})
				h.status(t, "POST", "/flows/resume", nil, "", 200)
				h.do(t, func(context.Context) error {
					for _, f := range h.app.view.Flows() {
						if f.Common().Intercepted() {
							t.Fatal("collection resume left interception")
						}
					}
					return nil
				})
			}},
			"test_kill": {func(t *testing.T, h *routeHarness) {
				h.do(t, func(context.Context) error {
					for _, f := range h.app.view.Flows() {
						f.Backup()
						f.Common().Intercept()
					}
					return nil
				})
				h.status(t, "POST", "/flows/42/kill", nil, "", 200)
				h.do(t, func(context.Context) error {
					if !h.app.view.GetByID("43").Common().Killable() {
						t.Fatal("single kill affected another flow")
					}
					return nil
				})
				h.status(t, "POST", "/flows/kill", nil, "", 200)
				h.do(t, func(context.Context) error {
					for _, f := range h.app.view.Flows() {
						if f.Common().Killable() {
							t.Fatal("collection kill left live flow")
						}
						if err := f.Revert(); err != nil {
							return err
						}
					}
					return nil
				})
			}},
			"test_flow_delete": {func(t *testing.T, h *routeHarness) {
				h.status(t, "DELETE", "/flows/42", nil, "", 200)
				h.do(t, func(context.Context) error {
					if h.app.view.GetByID("42") != nil {
						t.Fatal("deleted flow remains")
					}
					return nil
				})
				h.status(t, "DELETE", "/flows/1234", nil, "", 404)
			}},
			"test_flow_update": {testWebFlowUpdate},
			"test_flow_update_http_version_only": {func(t *testing.T, h *routeHarness) {
				h.put(t, "/flows/42", `{"response":{"http_version":"2.0"}}`, 200)
				h.do(t, func(context.Context) error {
					if got := h.app.view.GetByID("42").(*flow.HTTPFlow).Response.HTTPVersion; got != "2.0" {
						t.Fatalf("version=%q", got)
					}
					return nil
				})
			}},
			"test_flow_duplicate": {func(t *testing.T, h *routeHarness) {
				id := string(h.status(t, "POST", "/flows/42/duplicate", nil, "", 200))
				h.do(t, func(context.Context) error {
					if id == "42" || h.app.view.GetByID(id) == nil {
						t.Fatalf("invalid duplicate id=%q", id)
					}
					return nil
				})
			}},
			"test_flow_revert": {func(t *testing.T, h *routeHarness) {
				h.put(t, "/flows/42", `{"request":{"method":"PATCH"}}`, 200)
				h.status(t, "POST", "/flows/42/revert", nil, "", 200)
				h.do(t, func(context.Context) error {
					f := h.app.view.GetByID("42")
					if f.Modified() || f.(*flow.HTTPFlow).Request.Method != "GET" {
						t.Fatal("revert failed")
					}
					return nil
				})
			}},
			"test_flow_replay":  {testWebReplay},
			"test_flow_content": {testWebContent},
			"test_flow_content_returns_raw_content_when_decoding_fails": {func(t *testing.T, h *routeHarness) {
				raw := []byte("\xff\xffbroken gzip")
				h.do(t, func(context.Context) error {
					f := h.app.view.GetByID("42").(*flow.HTTPFlow)
					f.Response.Headers.Set("Content-Encoding", "gzip")
					f.Response.RawContent = raw
					return nil
				})
				got := h.status(t, "GET", "/flows/42/response/content.data", nil, "", 200)
				if diff := gocmp.Diff(raw, got); diff != "" {
					t.Fatal(diff)
				}
			}},
			"test_update_flow_content": {func(t *testing.T, h *routeHarness) {
				h.status(t, "POST", "/flows/42/request/content.data", []byte("new"), "", 200)
				h.do(t, func(context.Context) error {
					f := h.app.view.GetByID("42")
					if !f.Modified() || string(f.(*flow.HTTPFlow).Request.ContentOrRaw()) != "new" {
						t.Fatal("upload not backed up/updated")
					}
					return f.Revert()
				})
			}},
			"test_update_flow_content_multipart": {testWebMultipartContent},
			"test_flow_contentview": {func(t *testing.T, h *routeHarness) {
				for query, want := range map[string]string{"": "foo\nbar", "?lines=1": "foo\n"} {
					var got map[string]any
					if err := json.Unmarshal(h.status(t, "GET", "/flows/42/request/content/raw"+query, nil, "", 200), &got); err != nil {
						t.Fatal(err)
					}
					expected := map[string]any{"text": want, "description": "", "syntax_highlight": "none", "view_name": "Raw"}
					if diff := gocmp.Diff(expected, got); diff != "" {
						t.Fatal(diff)
					}
				}
				h.status(t, "GET", "/flows/42/messages/content/raw", nil, "", 400)
			}},
			"test_flow_contentview_websocket": {func(t *testing.T, h *routeHarness) {
				var got []map[string]any
				if err := json.Unmarshal(h.status(t, "GET", "/flows/43/messages/content/raw?lines=2", nil, "", 200), &got); err != nil {
					t.Fatal(err)
				}
				want := []map[string]any{{"text": "hello binary", "view_name": "Raw", "syntax_highlight": "none", "description": "", "from_client": true, "timestamp": float64(946681203)}, {"text": "hello text", "view_name": "Raw", "syntax_highlight": "none", "description": "", "from_client": true, "timestamp": float64(946681204)}}
				if diff := gocmp.Diff(want, got); diff != "" {
					t.Fatal(diff)
				}
			}},
			"test_commands": {func(t *testing.T, h *routeHarness) {
				var got map[string]map[string]any
				if err := json.Unmarshal(h.status(t, "GET", "/commands", nil, "", 200), &got); err != nil {
					t.Fatal(err)
				}
				if got["set"]["help"] == "" {
					t.Fatal("set command has no help")
				}
				want := map[string]map[string]any{
					"flow.resume": {
						"help":           "Resume flows if they are intercepted.",
						"parameters":     []any{map[string]any{"name": "flows", "type": "flow[]", "kind": "POSITIONAL_OR_KEYWORD"}},
						"return_type":    nil,
						"signature_help": "flow.resume flows",
					},
					"flow.set.options": {
						"help":           nil,
						"parameters":     []any{},
						"return_type":    "str[]",
						"signature_help": "flow.set.options  -> str[]",
					},
				}
				actual := map[string]map[string]any{"flow.resume": got["flow.resume"], "flow.set.options": got["flow.set.options"]}
				if diff := gocmp.Diff(want, actual); diff != "" {
					t.Fatalf("command descriptions (-want +got):\n%s", diff)
				}
			}},
			"test_command_execute": {func(t *testing.T, h *routeHarness) {
				for path, want := range map[string]string{"unknown": `{"error":"Unknown command: unknown"}`, "commands.history.get": `{"value":[]}`} {
					got := h.status(t, "POST", "/commands/"+path, nil, "", 200)
					var actual, expected any
					if err := json.Unmarshal(got, &actual); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal([]byte(want), &expected); err != nil {
						t.Fatal(err)
					}
					if diff := gocmp.Diff(expected, actual); diff != "" {
						t.Fatal(diff)
					}
				}
			}},
			"test_events": {func(t *testing.T, h *routeHarness) {
				var values []struct {
					ID      uint64 `json:"id"`
					Message string `json:"message"`
					Level   string `json:"level"`
				}
				if err := json.Unmarshal(h.status(t, "GET", "/events", nil, "", 200), &values); err != nil {
					t.Fatal(err)
				}
				if len(values) == 0 || values[0].Level != "info" {
					t.Fatal("initial info event missing")
				}
				h.do(t, func(context.Context) error {
					if values[0].ID != h.app.events.Records()[0].ID {
						t.Fatal("event identity differs from the store")
					}
					return nil
				})
			}},
			"test_options": {func(t *testing.T, h *routeHarness) {
				var got map[string]map[string]any
				if err := json.Unmarshal(h.status(t, "GET", "/options", nil, "", 200), &got); err != nil {
					t.Fatal(err)
				}
				if _, ok := got["anticache"]; !ok {
					t.Fatal("anticache missing")
				}
			}},
			"test_option_update": {func(t *testing.T, h *routeHarness) {
				h.put(t, "/options", `{"anticache":true}`, 200)
				h.put(t, "/options", `{"wtf":true}`, 400)
				h.put(t, "/options", `{"anticache":"foo"}`, 400)
			}},
			"test_option_save": {func(t *testing.T, h *routeHarness) { h.status(t, "POST", "/options/save", nil, "", 200) }},
			"test_err": {func(t *testing.T, h *routeHarness) {
				h.server.Close()
				h.app.protect = func(http.Handler, bool) http.Handler {
					return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("index handler failed") })
				}
				h.server = httptest.NewServer(h.app.handler())
				t.Cleanup(h.server.Close)
				h.status(t, "GET", "/", nil, "", 500)
			}},
			"test_process_list": {func(t *testing.T, h *routeHarness) {
				var got []map[string]any
				if err := json.Unmarshal(h.status(t, "GET", "/processes", nil, "", 200), &got); err != nil {
					t.Fatal(err)
				}
				if len(got) == 0 {
					t.Fatal("process list is empty")
				}
			}},
			"test_process_icon": {func(t *testing.T, h *routeHarness) {
				if got := h.status(t, "GET", "/executable-icon", nil, "", 400); !bytes.Contains(got, []byte("Missing 'path' parameter.")) {
					t.Fatalf("missing path error=%q", got)
				}
				response, body := h.fetch(t, "GET", "/executable-icon?path=invalid_path", nil, "")
				if response.StatusCode != 200 || response.Header.Get("Content-Type") != "image/png" || !bytes.Equal(body, transparentPNG) {
					t.Fatalf("fallback status=%d headers=%v body=%x", response.StatusCode, response.Header, body)
				}
			}},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) { test.run(t, newRouteHarness(t)) })
		}
	})
}

func testWebFlowUpdate(t *testing.T, h *routeHarness) {
	h.put(t, "/flows/42", `{"request":{"method":"PATCH","port":123,"headers":[["foo","bar"]],"trailers":[["foo","bar"]],"content":"req"},"response":{"reason":"Non-Authorisé","code":404,"headers":[["bar","baz"]],"trailers":[["foo","bar"]],"content":"resp"},"marked":":red_circle:","comment":"I'm a modified comment!"}`, 200)
	h.do(t, func(context.Context) error {
		f := h.app.view.GetByID("42").(*flow.HTTPFlow)
		if diff := gocmp.Diff([]any{"PATCH", 123, "bar", "bar", "req", "Non-Authorisé", 404, "baz", "bar", "resp", "I'm a modified comment!"}, []any{f.Request.Method, f.Request.Port, f.Request.Headers.Get("foo"), f.Request.Trailers.Get("foo"), f.Request.TextOrRaw(), f.Response.Reason, f.Response.StatusCode, f.Response.Headers.Get("bar"), f.Response.Trailers.Get("foo"), f.Response.TextOrRaw(), f.Comment}); diff != "" {
			t.Fatal(diff)
		}
		return nil
	})
	h.put(t, "/flows/42", `{"request":{"trailers":[["foo","baz"]]},"response":{"trailers":[["foo","baz"]]}}`, 200)
	h.do(t, func(context.Context) error {
		f := h.app.view.GetByID("42").(*flow.HTTPFlow)
		if f.Request.Trailers.Get("foo") != "baz" || f.Response.Trailers.Get("foo") != "baz" {
			t.Fatal("trailers not replaced")
		}
		return f.Revert()
	})
	for _, body := range []string{`{"foo":42}`, `{"request":{"foo":42}}`, `{"response":{"foo":42}}`} {
		h.put(t, "/flows/42", body, 400)
	}
	h.status(t, "PUT", "/flows/42", []byte("{}"), "", 400)
	h.status(t, "PUT", "/flows/42", []byte("!!"), "application/json", 400)
}

func testWebContent(t *testing.T, h *routeHarness) {
	h.do(t, func(context.Context) error {
		f := h.app.view.GetByID("42").(*flow.HTTPFlow)
		f.Backup()
		f.Response.Headers.Set("Content-Disposition", `inline; filename="filename.jpg"`)
		return nil
	})
	response, body := h.fetch(t, "GET", "/flows/42/response/content.data", nil, "")
	if string(body) != "message" || response.Header.Get("Content-Disposition") != `attachment; filename="filename.jpg"` {
		t.Fatalf("download=%q headers=%v", body, response.Header)
	}
	h.do(t, func(context.Context) error {
		f := h.app.view.GetByID("42").(*flow.HTTPFlow)
		f.Response.Headers.Del("Content-Disposition")
		f.Request.Path = "/foo/bar.jpg"
		return nil
	})
	response, _ = h.fetch(t, "GET", "/flows/42/response/content.data", nil, "")
	if response.Header.Get("Content-Disposition") != "attachment; filename=bar.jpg" {
		t.Fatal(response.Header)
	}
	h.do(t, func(context.Context) error {
		h.app.view.GetByID("42").(*flow.HTTPFlow).Response.SetContent([]byte{})
		return nil
	})
	if body := h.status(t, "GET", "/flows/42/response/content.data", nil, "", 200); len(body) != 0 {
		t.Fatalf("empty download=%q", body)
	}
}

func testWebReplay(t *testing.T, h *routeHarness) {
	received := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case received <- r.URL.Path:
		default:
		}
		_, _ = io.WriteString(w, "origin replay")
	}))
	t.Cleanup(origin.Close)
	h.do(t, func(context.Context) error {
		f := h.app.view.GetByID("42").(*flow.HTTPFlow)
		f.Live = false
		if err := f.Request.SetURL(origin.URL + "/replayed"); err != nil {
			return err
		}
		f.Request.SetHostHeader(strings.TrimPrefix(origin.URL, "http://"))
		return nil
	})
	h.status(t, "POST", "/flows/42/replay", nil, "", 200)
	select {
	case path := <-received:
		if path != "/replayed" {
			t.Fatalf("origin path=%q", path)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("real replay did not reach origin")
	}
}

func TestWebFlowJSON(t *testing.T) {
	tests := map[string]struct{ f flow.Flow }{"http": {testflow.TFlow(testflow.WithResponse)}, "websocket": {testflow.TFlow(testflow.WithResponse, testflow.WithWebSocket)}, "tcp": {testflow.TTCPFlow()}, "udp": {testflow.TUDPFlow()}, "dns": {testflow.TDNSFlow()}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			h := newRouteHarness(t)
			h.do(t, func(ctx context.Context) error {
				if _, err := h.app.master.Call(ctx, "view.clear"); err != nil {
					return err
				}
				h.app.view.Add(ctx, []flow.Flow{test.f})
				return nil
			})
			body := h.status(t, "GET", "/flows", nil, "", 200)
			var values []map[string]jsontext.Value
			if err := json.Unmarshal(body, &values); err != nil {
				t.Fatal(err)
			}
			if len(values) != 1 || string(values[0]["type"]) != `"`+name+`"` && name != "websocket" {
				t.Fatalf("flow type=%s", body)
			}
			if _, ok := values[0]["modified"]; !ok {
				t.Fatal("modified field absent")
			}
			if bytes.Contains(body, []byte(`"raw_content"`)) {
				t.Fatal("raw body leaked into JSON")
			}
		})
	}
}

func FuzzWebJSON(f *testing.F) {
	f.Add(`{"version":1,"uid":0,"destination":"viewer","stage":"owned"}`)
	f.Add(`{"version":1,"uid":0,"uid":1,"destination":"viewer","stage":"owned"}`)
	for _, seed := range []string{`{}`, `{"request":{"headers":[["x","a"],["x","b"]]}}`, `{"comment":"日本語"}`, `{"comment":"one","comment":"two"}`, `[`, "\xff", "1_000", "9223372036854775808", "-1"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<16 {
			return
		}
		_ = parseViewerOwner([]byte(input), viewerOwner{Version: 1, UID: 0, Destination: "viewer", Stage: "owned"})
		_, _ = lineLimit(input)
		request := httptest.NewRequestWithContext(t.Context(), "PUT", "/flows/42", strings.NewReader(input))
		request.Header.Set("Content-Type", "application/json")
		body, err := requestJSON(request)
		if err == nil {
			_, _ = jsonObject(body)
			_, _ = optionUpdate(body)
		}
	})
}

func FuzzWebUpload(f *testing.F) {
	var valid bytes.Buffer
	if err := flowio.NewWriter(&valid).Add(testflow.TFlow(testflow.WithResponse)); err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{"", "broken", "--boundary\r\nContent-Disposition: form-data; name=\"a\"; filename=\"a.txt\"\r\n\r\ndata\r\n--boundary--\r\n", valid.String()} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<16 {
			return
		}
		reader := multipart.NewReader(strings.NewReader(input), "boundary")
		for range 64 {
			part, err := reader.NextPart()
			if err != nil {
				break
			}
			_, _ = io.Copy(io.Discard, part)
			_ = part.Close()
		}
		m := master.New(master.Config{})
		t.Cleanup(func() {
			if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
				t.Error(err)
			}
		})
		v := view.New(m.Addons)
		if err := m.Addons.Add(t.Context(), v); err != nil {
			t.Fatal(err)
		}
		app := &application{master: m, view: v}
		request := httptest.NewRequestWithContext(t.Context(), "POST", "/flows/dump", strings.NewReader(input))
		response := httptest.NewRecorder()
		_ = app.dumpFlows(response, request)
		if response.Body.Len() != 0 {
			t.Fatalf("flow upload wrote an unexpected response: %q", response.Body.Bytes())
		}
	})
}
