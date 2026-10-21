// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
)

func TestScriptContext(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"log": {func(t *testing.T) {
			f := newFixture(t)
			store, err := eventstore.New()
			if err != nil {
				t.Fatal(err)
			}
			if err = f.master.Addons.Add(t.Context(), store); err != nil {
				t.Fatal(err)
			}
			handler := store.LogHandler(f.master.Addons)
			t.Cleanup(func() {
				if err := handler.Close(context.WithoutCancel(t.Context())); err != nil {
					t.Error(err)
				}
			})
			f.loader.cfg.Logger = slog.New(handler)
			f.requestScript("ctx.log(\"default\")\nctx.log.debug(\"debug\")\nctx.log.info(\"info\")\nctx.log.warn(\"warn\")\nctx.log.error(\"error\")\nctx.log.alert(\"alert\")")
			f.hook(addon.RequestHook{Flow: f.request()})
			if err = handler.Flush(t.Context()); err != nil {
				t.Fatal(err)
			}
			seen := map[string]string{}
			if err = f.master.Do(t.Context(), func(context.Context) error {
				for _, entry := range store.Entries() {
					_, message, ok := strings.Cut(entry.Msg, "] ")
					if !ok {
						continue
					}
					switch message {
					case "default", "debug", "info", "warn", "error", "alert":
						seen[message] = entry.LevelName()
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"default": "info", "debug": "debug", "info": "info", "warn": "warn", "error": "error", "alert": "alert"}
			if diff := gocmp.Diff(want, seen); diff != "" {
				t.Fatal(diff)
			}
			if err = handler.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
		}},
		"options_read": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("if ctx.options.script_max_steps != 0 or ctx.options.scripts == []:\n    fail(\"current option values\")\nf.comment = ctx.options.listen_host")
			x := f.request()
			f.hook(addon.RequestHook{Flow: x})
			f.wantLog("Addon error:", 0)
		}},
		"options_write": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("ctx.options.listen_port = 18080\nctx.options.listen_host = \"127.0.0.2\"")
			f.hook(addon.RequestHook{Flow: f.request()})
			if port := f.master.Options.OptInt("listen_port"); port == nil || *port != 18080 || f.master.Options.Str("listen_host") != "127.0.0.2" {
				t.Fatalf("real option Update missing: %s", f.logs.String())
			}
		}},
		"options_alias": {func(t *testing.T) {
			f := newFixture(t)
			f.load(f.file("alias.star", "o = ctx.options\ndef request(f):\n    o.listen_port = 18081\n    f.comment = str(o.listen_port)\n"))
			x := f.request()
			f.hook(addon.RequestHook{Flow: x})
			if port := f.master.Options.OptInt("listen_port"); x.Comment != "18081" || port == nil || *port != 18081 {
				t.Fatalf("capability alias lost active scope: %s", f.logs.String())
			}
		}},
		"commands_call": {func(t *testing.T) {
			f := newFixture(t)
			var got command.Path
			if err := f.master.Commands.Register("native.typed", func(_ context.Context, path command.Path, data []byte, n int) ([]byte, error) {
				got = path
				return append(data, byte(n)), nil
			}); err != nil {
				t.Fatal(err)
			}
			f.requestScript("result = ctx.master.commands.call(\"native.typed\", \"selected/path\", b\"\\x00\\xff\", 7)\nf.request.content = result")
			x := f.request()
			f.hook(addon.RequestHook{Flow: x})
			if got != "selected/path" {
				t.Fatalf("named Path conversion=%q", got)
			}
			if diff := gocmp.Diff([]byte{0, 255, 7}, x.Request.RawContent); diff != "" {
				t.Fatal(diff)
			}
		}},
		"loader_options": {func(t *testing.T) {
			f := newFixture(t)
			f.load(f.file("options.star", "def on_load(loader):\n    loader.add_option(\"custom\", \"sequence-of-str\", [\"one\"], \"Custom values.\", choices=[\"one\", \"two\"])\n"))
			opt, ok := f.master.Options.Lookup("custom")
			if !ok || opt.Help() != "Custom values." {
				t.Fatalf("custom option not registered: %s", f.logs.String())
			}
			if diff := gocmp.Diff([]string{"one"}, f.master.Options.Seq("custom")); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff([]string{"one", "two"}, opt.Choices()); diff != "" {
				t.Fatal(diff)
			}
		}},
		"loader_commands": {func(t *testing.T) {
			f := newFixture(t)
			f.load(f.file("commands.star", "state = {\"count\": 0}\ndef increment():\n    state[\"count\"] += 1\ndef on_load(loader):\n    loader.add_command(\"myaddon.inc\", increment, help=\"Increment the counter.\")\ndef request(f):\n    ctx.master.commands.call(\"myaddon.inc\")\n    f.comment = str(state[\"count\"])\n"))
			x := f.request()
			f.hook(addon.RequestHook{Flow: x})
			if x.Comment != "1" {
				t.Fatalf("registered script command failed: %s", f.logs.String())
			}
			f.load()
			if _, err := f.master.Call(t.Context(), "myaddon.inc"); err == nil {
				t.Fatal("owned command survived unload")
			}
		}},
		"shutdown": {func(t *testing.T) {
			f := newFixture(t)
			f.load(f.file("shutdown.star", "def running():\n    ctx.master.shutdown()\n"))
			if err := f.master.Run(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := f.loader.Close(); err != nil {
				t.Fatal(err)
			}
		}},
		"sleep_depth_one": {func(t *testing.T) {
			f := newFixture(t)
			entered := make(chan struct{})
			release := make(chan struct{})
			f.loader.sleepWait = func(ctx context.Context, d time.Duration) error {
				if d != time.Second {
					return fmt.Errorf("duration=%v", d)
				}
				_, err := addon.Concurrent(ctx, func(context.Context) error { return nil })
				if !errors.Is(err, addon.ErrNoDispatch) {
					return fmt.Errorf("I/O retained frame: %v", err)
				}
				close(entered)
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			f.requestScript("if f.request.path == \"/block\":\n    ctx.sleep(1)\nf.comment = \"finished\"")
			first := f.request()
			first.Request.Path = "/block"
			finished := make(chan error, 1)
			go func() { finished <- f.master.Addons.Hook(t.Context(), addon.RequestHook{Flow: first}) }()
			<-entered
			second := f.request()
			f.hook(addon.RequestHook{Flow: second})
			if second.Comment != "finished" {
				t.Fatal("other flow blocked while sleep released dispatch")
			}
			close(release)
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
			if first.Comment != "finished" {
				t.Fatalf("fresh frame not restored after sleep: %s", f.logs.String())
			}
		}},
		"sleep_nested_inline": {func(t *testing.T) {
			f := newFixture(t)
			called := false
			f.loader.sleepWait = func(ctx context.Context, d time.Duration) error {
				called = true
				_, err := addon.Concurrent(ctx, func(context.Context) error { return errors.New("unexpected release") })
				if !errors.Is(err, addon.ErrSyncContext) {
					return fmt.Errorf("inline path lost synchronous frame: %v", err)
				}
				return nil
			}
			f.load(f.file("inline.star", "def command():\n    ctx.sleep(1)\n    ctx.options.listen_port = 18082\ndef on_load(loader):\n    loader.add_command(\"script.inline\", command)\n"))
			if _, err := f.master.Call(t.Context(), "script.inline"); err != nil {
				t.Fatal(err)
			}
			if port := f.master.Options.OptInt("listen_port"); !called || port == nil || *port != 18082 {
				t.Fatalf("nested inline completion missing: %s", f.logs.String())
			}
		}},
		"http_get_depth_one": {func(t *testing.T) {
			f := newFixture(t)
			entered := make(chan struct{})
			release := make(chan struct{})
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				select {
				case <-release:
					_, _ = w.Write([]byte{0, 255})
				case <-r.Context().Done():
				}
			}))
			defer origin.Close()
			defer func() {
				if err := f.loader.Close(); err != nil {
					t.Error(err)
				}
			}()
			f.requestScript(fmt.Sprintf("if f.request.path == \"/block\":\n    response = ctx.http_get(%q)\n    if response.status_code != 200:\n        fail(\"status\")\n    f.request.content = response.content\nf.comment = \"finished\"", origin.URL))
			first := f.request()
			first.Request.Path = "/block"
			finished := make(chan error, 1)
			go func() { finished <- f.master.Addons.Hook(t.Context(), addon.RequestHook{Flow: first}) }()
			<-entered
			second := f.request()
			f.hook(addon.RequestHook{Flow: second})
			if second.Comment != "finished" {
				t.Fatal("HTTP operation held dispatch")
			}
			close(release)
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff([]byte{0, 255}, first.Request.RawContent); diff != "" {
				t.Fatalf("HTTP owned bytes/fresh frame: %s; %s", diff, f.logs.String())
			}
		}},
		"http_get_nested_inline": {func(t *testing.T) {
			f := newFixture(t)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("origin")) }))
			defer origin.Close()
			defer func() {
				if err := f.loader.Close(); err != nil {
					t.Error(err)
				}
			}()
			f.load(f.file("http-inline.star", fmt.Sprintf("def command():\n    response = ctx.http_get(%q)\n    ctx.options.listen_host = str(response.status_code)\ndef on_load(loader):\n    loader.add_command(\"script.http\", command)\n", origin.URL)))
			if _, err := f.master.Call(t.Context(), "script.http"); err != nil {
				t.Fatal(err)
			}
			if f.master.Options.Str("listen_host") != "200" {
				t.Fatalf("nested HTTP did not complete: %s", f.logs.String())
			}
		}},
		"cancel_refresh": {func(t *testing.T) {
			f := newFixture(t)
			entered := make(chan struct{})
			f.loader.sleepWait = func(ctx context.Context, _ time.Duration) error { close(entered); <-ctx.Done(); return ctx.Err() }
			f.requestScript("if f.request.path == \"/cancel\":\n    ctx.sleep(1)\nf.comment = \"safe\"")
			first := f.request()
			first.Request.Path = "/cancel"
			ctx, cancel := context.WithCancel(t.Context())
			finished := make(chan error, 1)
			go func() { finished <- f.master.Addons.Hook(ctx, addon.RequestHook{Flow: first}) }()
			<-entered
			cancel()
			if err := <-finished; !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled reacquisition=%v", err)
			}
			if first.Comment != "" {
				t.Fatal("evaluation continued without a dispatch frame")
			}
			second := f.request()
			f.hook(addon.RequestHook{Flow: second})
			if second.Comment != "safe" {
				t.Fatalf("stale shared scope survived cancellation: %s", f.logs.String())
			}
		}},
		"retained_context_reentry": {func(t *testing.T) {
			f := newFixture(t)
			f.load(f.file("reentry.star", "o = ctx.options\ndef nested():\n    o.listen_host = \"nested\"\ndef on_load(loader):\n    loader.add_command(\"script.nested\", nested)\ndef request(f):\n    ctx.master.commands.call(\"script.nested\")\n    f.comment = o.listen_host\n"))
			x := f.request()
			f.hook(addon.RequestHook{Flow: x})
			if x.Comment != "nested" {
				t.Fatalf("nested ordinary scope did not restore caller: %s", f.logs.String())
			}
			f.wantLog("Addon error:", 0)
		}},
	}
	t.Run("contracts", func(t *testing.T) {
		for name, test := range tests {
			t.Run(name, test.run)
		}
	})
}

func TestScriptHTTPGet(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"schemes": {func(t *testing.T) {
			for _, url := range []string{"file:///etc/passwd", "ftp://example.test/file", "http:///missing"} {
				f := newFixture(t)
				f.requestScript(fmt.Sprintf("ctx.http_get(%q)", url))
				f.hook(addon.RequestHook{Flow: f.request()})
				f.wantLog("Addon error:", 1)
			}
		}},
		"credentials": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("ctx.http_get(\"https://sensitive-user:sensitive-password@example.test/\")")
			f.hook(addon.RequestHook{Flow: f.request()})
			f.wantLog("rejects URL userinfo", 1)
			if strings.Contains(f.logs.String(), "sensitive-user") || strings.Contains(f.logs.String(), "sensitive-password") {
				t.Fatal("userinfo leaked into diagnostics")
			}
		}},
		"timeout": {func(t *testing.T) {
			f := newFixture(t)
			if f.loader.client.Timeout != 10*time.Second {
				t.Fatal("total HTTP budget changed")
			}
			f.loader.client.Timeout = 20 * time.Millisecond
			origin := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
			defer origin.Close()
			defer func() {
				if err := f.loader.Close(); err != nil {
					t.Error(err)
				}
			}()
			f.requestScript(fmt.Sprintf("ctx.http_get(%q)", origin.URL))
			f.hook(addon.RequestHook{Flow: f.request()})
			f.wantLog("Addon error:", 1)
		}},
		"redirect_limit": {func(t *testing.T) {
			f := newFixture(t)
			count := new(atomic.Int64)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				http.Redirect(w, r, "/again", http.StatusFound)
			}))
			defer origin.Close()
			defer func() {
				if err := f.loader.Close(); err != nil {
					t.Error(err)
				}
			}()
			f.requestScript(fmt.Sprintf("ctx.http_get(%q)", origin.URL))
			f.hook(addon.RequestHook{Flow: f.request()})
			f.wantLog("exceeds 3 redirects", 1)
			if got := count.Load(); got != 4 {
				t.Fatalf("redirect requests=%d want=4", got)
			}
		}},
		"response_limit": {func(t *testing.T) {
			f := newFixture(t)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(strings.Repeat("x", httpBodyLimit+1)))
			}))
			defer origin.Close()
			defer func() {
				if err := f.loader.Close(); err != nil {
					t.Error(err)
				}
			}()
			f.requestScript(fmt.Sprintf("ctx.http_get(%q)", origin.URL))
			f.hook(addon.RequestHook{Flow: f.request()})
			f.wantLog("response exceeds", 1)
		}},
		"header_limit": {func(t *testing.T) {
			f := newFixture(t)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Large", strings.Repeat("x", httpHeaderLimit+1))
				w.WriteHeader(200)
			}))
			defer origin.Close()
			defer func() {
				if err := f.loader.Close(); err != nil {
					t.Error(err)
				}
			}()
			f.requestScript(fmt.Sprintf("ctx.http_get(%q)", origin.URL))
			f.hook(addon.RequestHook{Flow: f.request()})
			f.wantLog("Addon error:", 1)
		}},
		"cancel": {func(t *testing.T) {
			f := newFixture(t)
			entered := make(chan struct{})
			origin := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }))
			defer origin.Close()
			defer func() {
				if err := f.loader.Close(); err != nil {
					t.Error(err)
				}
			}()
			f.requestScript(fmt.Sprintf("ctx.http_get(%q)", origin.URL))
			ctx, cancel := context.WithCancel(t.Context())
			finished := make(chan error, 1)
			request := f.request()
			go func() { finished <- f.master.Addons.Hook(ctx, addon.RequestHook{Flow: request}) }()
			<-entered
			cancel()
			if err := <-finished; !errors.Is(err, context.Canceled) {
				t.Fatalf("HTTP cancellation=%v", err)
			}
		}},
		"transport_reuse": {func(t *testing.T) {
			f := newFixture(t)
			peers := make(chan string, 2)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				peers <- r.RemoteAddr
				_, _ = w.Write([]byte("ok"))
			}))
			defer origin.Close()
			defer func() {
				if err := f.loader.Close(); err != nil {
					t.Error(err)
				}
			}()
			transport := f.loader.transport
			f.requestScript(fmt.Sprintf("ctx.http_get(%q)", origin.URL))
			f.hook(addon.RequestHook{Flow: f.request()})
			f.hook(addon.RequestHook{Flow: f.request()})
			firstPeer, secondPeer := <-peers, <-peers
			if f.loader.transport != transport || firstPeer != secondPeer {
				t.Fatalf("HTTP transport not reused: %s -> %s", firstPeer, secondPeer)
			}
		}},
		"proxy_environment": {func(t *testing.T) {
			f := newFixture(t)
			t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
			t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
			t.Setenv("NO_PROXY", "")
			if f.loader.transport.Proxy != nil {
				t.Fatal("HTTP inherited proxy environment")
			}
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("direct")) }))
			defer origin.Close()
			defer func() {
				if err := f.loader.Close(); err != nil {
					t.Error(err)
				}
			}()
			f.requestScript(fmt.Sprintf("f.comment = str(ctx.http_get(%q).status_code)", origin.URL))
			x := f.request()
			f.hook(addon.RequestHook{Flow: x})
			if x.Comment != "200" {
				t.Fatalf("direct HTTP failed: %s", f.logs.String())
			}
		}},
		"self_proxy": {func(t *testing.T) {
			f := newFixture(t)
			f.loader.cfg.ListenAddrs = nil
			f.requestScript("ctx.http_get(\"http://127.0.0.1:8080\")")
			f.hook(addon.RequestHook{Flow: f.request()})
			f.wantLog("listener-address capability", 1)
			f.loader.cfg.ListenAddrs = func() []connection.Address { return []connection.Address{{Host: "0.0.0.0", Port: 8080}} }
			f.hook(addon.RequestHook{Flow: f.request()})
			f.wantLog("rejects this master's proxy listener", 1)
		}},
		"concurrency": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("ctx.http_get(\"http://127.0.0.1:8080\")")
			entry := f.loader.entries[0]
			for range 32 {
				entry.httpSlots <- struct{}{}
			}
			f.hook(addon.RequestHook{Flow: f.request()})
			f.wantLog("busy: 32 operations", 1)
			for range 32 {
				<-entry.httpSlots
			}
			if len(entry.httpSlots) != 0 {
				t.Fatal("admission leaked")
			}
		}},
		"body_close": {func(t *testing.T) {
			f := newFixture(t)
			entered := make(chan struct{})
			canceled := make(chan struct{})
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "2097152")
				_, _ = w.Write([]byte(strings.Repeat("x", httpBodyLimit+1)))
				w.(http.Flusher).Flush()
				close(entered)
				<-r.Context().Done()
				close(canceled)
			}))
			defer origin.Close()
			defer func() {
				if err := f.loader.Close(); err != nil {
					t.Error(err)
				}
			}()
			f.requestScript(fmt.Sprintf("ctx.http_get(%q)", origin.URL))
			f.hook(addon.RequestHook{Flow: f.request()})
			<-entered
			select {
			case <-canceled:
			case <-t.Context().Done():
				t.Fatal("oversized response body was not closed")
			}
			f.wantLog("response exceeds", 1)
		}},
	}
	t.Run("bounds", func(t *testing.T) {
		for name, test := range tests {
			t.Run(name, test.run)
		}
	})
}
