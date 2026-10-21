// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.starlark.net/starlark"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buffer.String() }

type scriptFixture struct {
	t      *testing.T
	master *master.Master
	loader *Loader
	logs   *lockedBuffer
	ticks  chan time.Time
	dir    string
}

func newFixture(t *testing.T) *scriptFixture {
	t.Helper()
	logs := new(lockedBuffer)
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	m := master.New(master.Config{Logger: logger})
	loader := New(m, Config{Logger: logger, ListenAddrs: func() []connection.Address { return nil }})
	ticks := make(chan time.Time)
	loader.ticks = ticks
	f := &scriptFixture{t: t, master: m, loader: loader, logs: logs, ticks: ticks, dir: t.TempDir()}
	t.Cleanup(func() {
		if err := loader.Close(); err != nil {
			t.Error(err)
		}
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	if err := m.Addons.Add(t.Context(), loader); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *scriptFixture) file(name, data string) string {
	f.t.Helper()
	path := filepath.Join(f.dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		f.t.Fatal(err)
	}
	return path
}

func (f *scriptFixture) load(paths ...string) {
	f.t.Helper()
	if err := f.master.Do(f.t.Context(), func(ctx context.Context) error { return f.master.Options.Update(ctx, map[string]any{"scripts": paths}) }); err != nil {
		f.t.Fatal(err)
	}
}

func (f *scriptFixture) request() *flow.HTTPFlow {
	f.t.Helper()
	req, err := httpmsg.MakeRequest("GET", "http://example.test/start", []byte{}, httpmsg.Headers{{Name: []byte("Host"), Value: []byte("example.test")}})
	if err != nil {
		f.t.Fatal(err)
	}
	client := connection.NewClient(connection.Address{Host: "127.0.0.1", Port: 1234}, connection.Address{Host: "127.0.0.1", Port: 8080}, 0)
	server := connection.NewServer(&connection.Address{Host: "example.test", Port: 80})
	flow := flow.NewHTTPFlow(client, server, true)
	flow.Request = req
	return flow
}

func (f *scriptFixture) hook(hook addon.Hook) {
	f.t.Helper()
	if err := f.master.Addons.Hook(f.t.Context(), hook); err != nil {
		f.t.Fatal(err)
	}
}

func (f *scriptFixture) wantLog(text string, count int) {
	f.t.Helper()
	if got := strings.Count(f.logs.String(), text); got != count {
		f.t.Fatalf("log %q count=%d, want=%d; records:\n%s", text, got, count, f.logs.String())
	}
}

func (f *scriptFixture) poll() {
	f.t.Helper()
	done := make(chan struct{})
	f.loader.onPoll = func() { close(done) }
	select {
	case f.ticks <- time.Time{}:
	case <-f.t.Context().Done():
		f.t.Fatal(f.t.Context().Err())
	}
	select {
	case <-done:
	case <-f.t.Context().Done():
		f.t.Fatal(f.t.Context().Err())
	}
}

func (f *scriptFixture) updateSource(path, text string, advance time.Duration) {
	f.t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		f.t.Fatal(err)
	}
	mtime := st.ModTime().Add(advance)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		f.t.Fatal(err)
	}
}

func TestScriptOptions(t *testing.T) {
	tests := map[string]struct {
		typ  options.Type
		def  any
		help string
	}{
		"scripts":          {options.TypeSeq, []string{}, "Execute a script."},
		"script_max_steps": {options.TypeInt, 0, "Maximum number of Starlark execution steps per script hook call. 0 means no limit."},
	}
	t.Run("options", func(t *testing.T) {
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				f := newFixture(t)
				opt, ok := f.master.Options.Lookup(name)
				if !ok {
					t.Fatalf("missing option %q", name)
				}
				if opt.Type() != test.typ || opt.Help() != test.help {
					t.Fatalf("metadata: type=%v help=%q", opt.Type(), opt.Help())
				}
				if diff := gocmp.Diff(test.def, opt.Default()); diff != "" {
					t.Fatal(diff)
				}
			})
		}
	})
}

func TestScriptLoader(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"init_unfrozen": {func(t *testing.T) {
			f := newFixture(t)
			f.load(f.file("mutable.star", "state = {}\ndef request(f):\n    state[\"value\"] = f.id\n    f.comment = state[\"value\"]\n"))
			flow := f.request()
			f.hook(addon.RequestHook{Flow: flow})
			if flow.Comment != flow.ID {
				t.Fatalf("ordinary globals unexpectedly immutable: %s", f.logs.String())
			}
		}},
		"counter_persists": {func(t *testing.T) {
			f := newFixture(t)
			f.load(f.file("counter.star", "state = {\"n\": 0}\ndef request(f):\n    state[\"n\"] += 1\n    f.comment = str(state[\"n\"])\n"))
			for n := range 3 {
				flow := f.request()
				f.hook(addon.RequestHook{Flow: flow})
				if flow.Comment != fmt.Sprint(n+1) {
					t.Fatalf("counter=%q; logs=%s", flow.Comment, f.logs.String())
				}
			}
		}},
		"lifecycle_reload": {func(t *testing.T) {
			f := newFixture(t)
			path := f.file("reload.star", "def request(f):\n    f.comment = \"old\"\n")
			f.load(path)
			f.updateSource(path, "def request(f):\n    f.comment = \"new\"\n", time.Second)
			f.poll()
			flow := f.request()
			f.hook(addon.RequestHook{Flow: flow})
			if flow.Comment != "new" {
				t.Fatalf("reload effect=%q; logs=%s", flow.Comment, f.logs.String())
			}
		}},
		"remove_cancel": {func(t *testing.T) {
			f := newFixture(t)
			path := f.file("removed.star", "def done():\n    ctx.log(\"removed-done\")\n")
			f.load(path)
			f.load()
			f.wantLog("removed-done", 1)
			if f.master.Addons.Get("script:"+path) != nil {
				t.Fatal("removed module still registered")
			}
			f.poll()
			if len(f.loader.entries) != 0 {
				t.Fatal("watcher revived removed module")
			}
		}},
		"reorder_no_reinit": {func(t *testing.T) {
			f := newFixture(t)
			a := f.file("a.star", "ctx.log(\"init-a\")\ndef request(f):\n    f.comment += \"a\"\n")
			b := f.file("b.star", "ctx.log(\"init-b\")\ndef request(f):\n    f.comment += \"b\"\n")
			f.load(a, b)
			f.load(b, a)
			flow := f.request()
			f.hook(addon.RequestHook{Flow: flow})
			if flow.Comment != "ba" {
				t.Fatalf("order=%q", flow.Comment)
			}
			f.wantLog("init-a", 1)
			f.wantLog("init-b", 1)
		}},
		"delete_path": {func(t *testing.T) {
			f := newFixture(t)
			path := f.file("deleted.star", "def done():\n    ctx.log(\"deleted-done\")\n")
			f.load(path)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			f.poll()
			if len(f.master.Options.Seq("scripts")) != 0 || len(f.loader.entries) != 0 {
				t.Fatal("deleted source still configured")
			}
			f.wantLog("deleted-done", 1)
		}},
		"parse_error_once": {func(t *testing.T) {
			f := newFixture(t)
			f.load(f.file("broken.star", "def request(:\n"))
			f.poll()
			f.poll()
			f.wantLog("error in script", 1)
		}},
		"step_limit": {func(t *testing.T) {
			f := newFixture(t)
			if err := f.master.Options.Update(t.Context(), map[string]any{"script_max_steps": 200}); err != nil {
				t.Fatal(err)
			}
			f.load(f.file("limited.star", "def request(f):\n    for n in range(10000):\n        f.comment = str(n)\n"))
			f.hook(addon.RequestHook{Flow: f.request()})
			f.wantLog("too many steps", 1)
		}},
		"step_zero": {func(t *testing.T) {
			f := newFixture(t)
			f.load(f.file("unlimited.star", "def request(f):\n    for n in range(2000):\n        f.comment = str(n)\n"))
			flow := f.request()
			f.hook(addon.RequestHook{Flow: flow})
			if flow.Comment != "1999" {
				t.Fatalf("zero budget did not remain unlimited: %s", f.logs.String())
			}
		}},
		"step_negative": {func(t *testing.T) {
			f := newFixture(t)
			err := f.master.Do(t.Context(), func(ctx context.Context) error {
				return f.master.Options.Update(ctx, map[string]any{"script_max_steps": -1})
			})
			if err == nil {
				t.Fatal("negative step budget accepted")
			}
			if f.master.Options.Int("script_max_steps") != 0 {
				t.Fatal("rejected step budget was not rolled back")
			}
		}},
		"mtime_monotonic": {func(t *testing.T) {
			f := newFixture(t)
			path := f.file("mtime.star", "ctx.log(\"first-init\")\n")
			f.load(path)
			f.updateSource(path, "ctx.log(\"backwards-init\")\n", -time.Second)
			f.poll()
			f.wantLog("first-init", 1)
			f.wantLog("backwards-init", 0)
			f.updateSource(path, "ctx.log(\"later-init\")\n", 2*time.Second)
			f.poll()
			f.wantLog("later-init", 1)
		}},
		"partial_startup_cleanup": {func(t *testing.T) {
			f := newFixture(t)
			path := f.file("failed-load.star", "def command():\n    pass\ndef on_load(loader):\n    loader.add_command(\"owned.failed\", command)\n    fail(\"load failed\")\n")
			f.load(path)
			for name := range f.master.Commands.Commands() {
				if name == "owned.failed" {
					t.Fatal("failed load retained command")
				}
			}
			deferred := newFixture(t)
			if err := deferred.master.Do(t.Context(), func(ctx context.Context) error {
				return deferred.master.Options.UpdateDeferred(ctx, map[string]any{"deferred_custom": "invalid-bool"})
			}); err != nil {
				t.Fatal(err)
			}
			deferredPath := deferred.file("deferred.star", "def command():\n    ctx.options.listen_host = \"recovered\"\ndef on_load(loader):\n    loader.add_option(\"deferred_custom\", \"bool\", False, \"Deferred value.\")\n    loader.add_command(\"owned.deferred\", command)\ndef done():\n    ctx.log(\"deferred-cleanup-done\")\n")
			deferred.load(deferredPath)
			if deferred.master.Addons.Get("script:"+deferredPath) != nil {
				t.Fatal("deferred option failure retained the registered script")
			}
			for name := range deferred.master.Commands.Commands() {
				if name == "owned.deferred" {
					t.Fatal("deferred option failure retained an owned command")
				}
			}
			deferred.wantLog("deferred-cleanup-done", 1)
			deferred.wantLog("error in script", 1)
			deferred.updateSource(deferredPath, "def command():\n    ctx.options.listen_host = \"recovered\"\ndef on_load(loader):\n    loader.add_option(\"deferred_custom\", \"str\", \"\", \"Deferred value.\")\n    loader.add_command(\"owned.deferred\", command)\n", time.Second)
			deferred.poll()
			if deferred.master.Addons.Get("script:"+deferredPath) == nil {
				t.Fatalf("same-name reload failed after deferred cleanup: %s", deferred.logs.String())
			}
			if _, err := deferred.master.Call(t.Context(), "owned.deferred"); err != nil {
				t.Fatal(err)
			}
			if deferred.master.Options.Str("listen_host") != "recovered" {
				t.Fatal("reloaded owned command did not run")
			}
			if err := f.loader.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.loader.Close(); err != nil {
				t.Fatal(err)
			}
		}},
		"path_replacement": {func(t *testing.T) {
			f := newFixture(t)
			target := f.file("target.star", "def request(f):\n    f.comment = \"first\"\n")
			alias := filepath.Join(f.dir, "selected.star")
			if err := os.Symlink(target, alias); err != nil {
				t.Fatal(err)
			}
			f.load(alias)
			replacement := f.file("replacement.star", "def request(f):\n    f.comment = \"second\"\n")
			st, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			next := st.ModTime().Add(time.Second)
			if err := os.Chtimes(replacement, next, next); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(alias); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(replacement, alias); err != nil {
				t.Fatal(err)
			}
			f.poll()
			flow := f.request()
			f.hook(addon.RequestHook{Flow: flow})
			if flow.Comment != "second" {
				t.Fatalf("symlink replacement not re-resolved: %s", f.logs.String())
			}
		}},
		"source_size_limit": {func(t *testing.T) {
			f := newFixture(t)
			path := f.file("large.star", "#"+strings.Repeat("x", sourceLimit))
			f.load(path)
			f.wantLog("source exceeds", 1)
			if f.loader.entries[0].module != nil {
				t.Fatal("oversized script initialized")
			}
			exact := f.file("exact.star", "#"+strings.Repeat("x", sourceLimit-1))
			src, err := readSource(exact)
			if err != nil || len(src.data) != sourceLimit {
				t.Fatalf("exact limit rejected: %v", err)
			}
		}},
		"shutdown_join": {func(t *testing.T) {
			retiring := newFixture(t)
			path := retiring.file("retire.star", "state = {\"work\": 0, \"done\": 0}\ndef work():\n    state[\"work\"] += 1\ndef on_load(loader):\n    loader.add_command(\"script.afterdone\", work)\ndef request(f):\n    work()\ndef done():\n    state[\"done\"] += 1\n")
			retiring.load(path)
			module := retiring.loader.entries[0].module
			retiring.hook(addon.RequestHook{Flow: retiring.request()})
			retiring.hook(addon.DoneHook{})
			retiring.hook(addon.RequestHook{Flow: retiring.request()})
			retiring.hook(addon.DoneHook{})
			if _, err := retiring.master.Call(t.Context(), "script.afterdone"); err == nil {
				t.Fatal("Done admitted a new script command")
			}
			retiring.updateSource(path, "ctx.log(\"unexpected-after-done-init\")\n", time.Second)
			retiring.poll()
			retiring.wantLog("unexpected-after-done-init", 0)
			newPath := retiring.file("new-after-done.star", "ctx.log(\"unexpected-new-script\")\n")
			if err := retiring.master.Do(t.Context(), func(ctx context.Context) error {
				return retiring.master.Options.Update(ctx, map[string]any{"scripts": []string{newPath}})
			}); err == nil {
				t.Fatal("Done admitted another source load")
			}
			if err := retiring.master.Do(t.Context(), func(context.Context) error {
				state := module.members["state"].(*starlark.Dict)
				work, _, err := state.Get(starlark.String("work"))
				if err != nil {
					return err
				}
				done, _, err := state.Get(starlark.String("done"))
				if err != nil {
					return err
				}
				if work.String() != "1" || done.String() != "1" || retiring.loader.entries[0].module != module {
					return fmt.Errorf("Done admitted work or repeated teardown: work=%s done=%s", work, done)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := retiring.loader.Close(); err != nil {
				t.Fatal(err)
			}
			f := newFixture(t)
			f.load(f.file("join.star", "def running():\n    ctx.master.shutdown()\n"))
			if err := f.master.Run(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := f.loader.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-f.loader.ctx.Done():
			default:
				t.Fatal("Close did not cancel")
			}
		}},
	}
	t.Run("contracts", func(t *testing.T) {
		for name, test := range tests {
			t.Run(name, test.run)
		}
	})
}
