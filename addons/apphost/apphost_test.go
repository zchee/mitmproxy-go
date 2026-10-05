// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package apphost

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

// TestRequest ports all five exchanges of test_asgi_full from upstream
// test/mitmproxy/addons/test_asgiapp.py. ASGI/WSGI adapters are replaced by
// http.Handler; the request hook, request parameters and body, and error
// responses are exercised through the real addon dispatcher.
func TestRequest(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		method, path, body string
		handler            http.HandlerFunc
		status             int
		want, log          string
	}{
		"success: basic app": {"GET", "/", "", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "testapp") }, 200, "testapp", ""},
		"success: parameters": {"GET", "/parameters?param1=1&param2=2", "", func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintf(w, `{"param1": "%s", "param2": "%s"}`, r.URL.Query().Get("param1"), r.URL.Query().Get("param2"))
		}, 200, `{"param1": "1", "param2": "2"}`, ""},
		"success: body": {"POST", "/requestbody", "Hello!", func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				panic(err)
			}
			_, _ = fmt.Fprintf(w, `{"body": "%s"}`, body)
		}, 200, `{"body": "Hello!"}`, ""},
		"error: panic":       {"GET", "/?foo=bar", "", func(http.ResponseWriter, *http.Request) { panic("errapp") }, 500, "ASGI Error.", "errapp"},
		"error: no response": {"GET", "/", "", func(http.ResponseWriter, *http.Request) {}, 500, "ASGI Error.", "no response sent"},
		"error: partial response then panic": {"GET", "/", "", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "partial")
			panic("partial panic")
		}, 500, "ASGI Error.", "partial panic"},
		"success: explicit empty response": {"GET", "/", "", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }, 204, "", ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			manager := addon.NewManager(options.New(), command.NewManager(), addon.Config{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
			t.Cleanup(manager.Close)
			if err := manager.Add(t.Context(), New(tt.handler, "testapp", 80)); err != nil {
				t.Fatal(err)
			}
			f := testflow.TFlow()
			var err error
			f.Request, err = httpmsg.MakeRequest(tt.method, "http://testapp"+tt.path, []byte(tt.body), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if f.Response == nil {
				t.Fatal("request hook did not set a response")
			}
			if diff := gocmp.Diff(tt.status, f.Response.StatusCode); diff != "" {
				t.Error(diff)
			}
			if diff := gocmp.Diff(tt.want, string(f.Response.RawContent)); diff != "" {
				t.Error(diff)
			}
			if tt.log != "" && !strings.Contains(logs.String(), tt.log) {
				t.Errorf("log %q lacks %q", logs.String(), tt.log)
			}
		})
	}
}

func TestHead(t *testing.T) {
	t.Parallel()
	manager := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	app := New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "42")
		w.WriteHeader(http.StatusOK)
	}), "address", 0)
	if err := manager.Add(t.Context(), app); err != nil {
		t.Fatal(err)
	}
	f := testflow.TFlow()
	f.Request.Method = http.MethodHead
	if err := manager.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if f.Response == nil {
		t.Fatal("missing response")
	}
	if diff := gocmp.Diff("42", f.Response.Headers.Get("content-length")); diff != "" {
		t.Error(diff)
	}
	if len(f.Response.RawContent) != 0 {
		t.Fatal("HEAD response has a body")
	}
}

func TestMatching(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		port   int
		change func(*flow.HTTPFlow)
		serve  bool
	}{
		"success: any port":              {0, func(*flow.HTTPFlow) {}, true},
		"success: exact port":            {22, func(*flow.HTTPFlow) {}, true},
		"success: host header preferred": {0, func(f *flow.HTTPFlow) { f.Request.Host = "other"; f.Request.Headers.Set("Host", "address:22") }, true},
		"ignore: wrong host":             {0, func(f *flow.HTTPFlow) { f.Request.Host = "other" }, false},
		"ignore: wrong port":             {80, func(*flow.HTTPFlow) {}, false},
		"ignore: replayed flow":          {0, func(f *flow.HTTPFlow) { f.Live = false }, false},
		"ignore: error":                  {0, func(f *flow.HTTPFlow) { f.Error = testflow.TErr() }, false},
		"ignore: response already set":   {0, func(f *flow.HTTPFlow) { f.Response = testflow.TResp() }, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			called := false
			app := New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(200) }), "address", tt.port)
			manager := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
			t.Cleanup(manager.Close)
			if err := manager.Add(t.Context(), app); err != nil {
				t.Fatal(err)
			}
			f := testflow.TFlow()
			tt.change(f)
			before := f.Response
			if err := manager.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.serve, called); diff != "" {
				t.Error(diff)
			}
			if !tt.serve && f.Response != before {
				t.Error("ignored flow's response changed")
			}
		})
	}
}

func TestConcurrentSnapshot(t *testing.T) {
	t.Parallel()
	manager := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	f := testflow.TFlow()
	app := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Re-entering the dispatcher here proves the handler runs outside the
		// dispatch lock with a fresh context, not the stale hook frame.
		if err := manager.Do(r.Context(), func(context.Context) error {
			if f.Response != nil {
				t.Error("partially built response escaped the handler")
			}
			f.Request.RawContent[0] = 'X'
			f.Request.Headers[0].Value[0] = 'X'
			return nil
		}); err != nil {
			t.Error(err)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if diff := gocmp.Diff("content", string(body)); diff != "" {
			t.Error(diff)
		}
		if diff := gocmp.Diff("qvalue", r.Header.Get("header")); diff != "" {
			t.Error(diff)
		}
		if diff := gocmp.Diff("127.0.0.1:22", r.RemoteAddr); diff != "" {
			t.Error(diff)
		}
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		_, _ = io.WriteString(w, "complete")
	}), "address", 22)
	if err := manager.Add(t.Context(), app); err != nil {
		t.Fatal(err)
	}
	if err := manager.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if f.Response == nil {
		t.Fatal("missing response")
	}
	if diff := gocmp.Diff([]string{"a=1", "b=2"}, f.Response.Headers.GetAll("set-cookie")); diff != "" {
		t.Error(diff)
	}
}
