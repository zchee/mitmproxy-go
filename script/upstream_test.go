// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
)

// These cases translate test/mitmproxy/addons/test_script.py at the repository's
// pinned upstream commit. Python classes become explicit module-valued children;
// owned files and the real registries replace Python's testing substitutions.
func TestScriptUpstream(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"test_load_script": {func(t *testing.T) {
				f := newFixture(t)
				path := f.file("recorder.star", "def child_request(f):\n    f.comment = \"child-called\"\naddons = [module(\"recorder\", request=child_request)]\n")
				f.load(path)
				if f.master.Addons.Get("script:"+path+"/0:recorder") == nil {
					t.Fatal("nested recorder not registered")
				}
				flow := f.request()
				f.hook(addon.RequestHook{Flow: flow})
				if flow.Comment != "child-called" {
					t.Fatalf("nested request missing: %s", f.logs.String())
				}
				if _, err := readSource(path + ".missing"); err == nil {
					t.Fatal("missing source accepted")
				}
				f.load(f.file("syntax.star", "this is invalid syntax"))
				f.wantLog("error in script", 1)
			}},
			"test_load_fullname": {func(t *testing.T) {
				f := newFixture(t)
				a := f.file("a/addon.star", "def request(f):\n    f.comment += \"a\"\n")
				b := f.file("b/addon.star", "def request(f):\n    f.comment += \"b\"\n")
				f.load(a, b)
				if f.master.Addons.Get("script:"+a) == nil || f.master.Addons.Get("script:"+b) == nil {
					t.Fatal("same-basename script identity collision")
				}
				flow := f.request()
				f.hook(addon.RequestHook{Flow: flow})
				if flow.Comment != "ab" {
					t.Fatalf("both scripts did not run: %q", flow.Comment)
				}
			}},
			"test_order": {func(t *testing.T) {
				f := newFixture(t)
				recorder := f.file("recorder.star", "def on_load(loader):\n    ctx.log(\"recorder load\")\ndef configure(updated):\n    ctx.log(\"recorder configure\")\ndef running():\n    ctx.log(\"recorder running\")\ndef done():\n    ctx.log(\"recorder done\")\n")
				shutdown := f.file("shutdown.star", "def running():\n    ctx.master.shutdown()\n")
				f.load(recorder, shutdown)
				if err := f.master.Run(t.Context()); err != nil {
					t.Fatal(err)
				}
				logs := f.logs.String()
				prior := -1
				for _, marker := range []string{"recorder load", "recorder configure", "recorder running", "recorder done"} {
					index := strings.Index(logs, marker)
					if index <= prior {
						t.Fatalf("startup ordering at %q: %s", marker, logs)
					}
					prior = index
					f.wantLog(marker, 1)
				}
			}},
		}
		for name, test := range tests {
			t.Run(name, test.run)
		}
		t.Run("TestScript", func(t *testing.T) {
			tests := map[string]struct{ run func(*testing.T) }{
				"test_notfound": {func(t *testing.T) {
					f := newFixture(t)
					err := f.master.Do(t.Context(), func(ctx context.Context) error {
						return f.master.Options.Update(ctx, map[string]any{"scripts": []string{f.dir + "/missing.star"}})
					})
					if err == nil || !strings.Contains(err.Error(), "No such script:") {
						t.Fatalf("missing-path error=%v", err)
					}
					if len(f.loader.entries) != 0 {
						t.Fatal("failed path registered")
					}
				}},
				"test_quotes_around_filename": {func(t *testing.T) {
					f := newFixture(t)
					path := f.file("quoted.star", "def request(f):\n    f.comment = \"quoted\"\n")
					f.load("\"" + path + "\"")
					if f.loader.entries[0].fullpath != path {
						t.Fatal("quotes retained in opened path")
					}
					flow := f.request()
					f.hook(addon.RequestHook{Flow: flow})
					if flow.Comment != "quoted" {
						t.Fatal(f.logs.String())
					}
				}},
				"test_simple": {func(t *testing.T) {
					f := newFixture(t)
					path := f.file("recorder.star", "events = []\ndef on_load(loader):\n    events.append(\"load\")\ndef configure(updated):\n    events.append(\"configure\")\ndef request(f):\n    events.append(\"request\")\n    f.comment = \",\".join(events)\n")
					f.load(path)
					flow := f.request()
					f.hook(addon.RequestHook{Flow: flow})
					if flow.Comment != "load,configure,request" {
						t.Fatalf("recorder order=%q; %s", flow.Comment, f.logs.String())
					}
				}},
				"test_reload": {func(t *testing.T) {
					f := newFixture(t)
					path := f.file("reload.star", "ctx.log(\"loaded-first\")\n")
					f.load(path)
					f.updateSource(path, "ctx.log(\"loaded-replacement\")\n", time.Second)
					f.poll()
					f.wantLog("loaded-first", 1)
					f.wantLog("loaded-replacement", 1)
				}},
				"test_exception": {func(t *testing.T) {
					f := newFixture(t)
					path := f.file("error.star", "def on_load(loader):\n    ctx.log(\"error load\")\ndef request(f):\n    fail(\"Error!\")\n")
					f.load(path)
					f.hook(addon.RequestHook{Flow: f.request()})
					f.wantLog("error load", 1)
					f.wantLog("Addon error:", 1)
					f.wantLog("Error!", 1)
					if !strings.Contains(f.logs.String(), "error.star") {
						t.Fatal("source path missing from diagnostic")
					}
				}},
				"test_configure_error": {func(t *testing.T) {
					f := newFixture(t)
					f.load(f.file("configure.star", "def configure(updated):\n    fail(\"Options Error\")\n"))
					f.wantLog("error in script", 1)
					f.wantLog("Options Error", 1)
				}},
				"test_addon": {func(t *testing.T) {
					f := newFixture(t)
					f.load(f.file("addon.star", "events = []\ndef on_load(loader):\n    events.append(\"scriptload\")\ndef configure(updated):\n    events.append(\"scriptconfigure\")\ndef child_load(loader):\n    events.append(\"addonload\")\ndef child_configure(updated):\n    events.append(\"addonconfigure\")\ndef request(f):\n    f.comment = \",\".join(events)\naddons = [module(\"child\", on_load=child_load, configure=child_configure)]\n"))
					flow := f.request()
					f.hook(addon.RequestHook{Flow: flow})
					if flow.Comment != "scriptload,addonload,scriptconfigure,addonconfigure" {
						t.Fatalf("module/child lifecycle=%q; %s", flow.Comment, f.logs.String())
					}
				}},
			}
			for name, test := range tests {
				t.Run(name, test.run)
			}
		})
		t.Run("TestScriptLoader", func(t *testing.T) {
			tests := map[string]struct{ run func(*testing.T) }{
				"test_simple": {func(t *testing.T) {
					f := newFixture(t)
					f.hook(addon.RunningHook{})
					path := f.file("simple.star", "def running():\n    ctx.log(\"late-running\")\n")
					f.load(path)
					if f.master.Addons.Len() != 1 || len(f.loader.Addons()) != 1 {
						t.Fatal("loader changed the master chain")
					}
					f.wantLog("late-running", 1)
					f.load()
					if f.master.Addons.Len() != 1 || len(f.loader.Addons()) != 0 {
						t.Fatal("unload changed the master chain")
					}
				}},
				"test_dupes": {func(t *testing.T) {
					f := newFixture(t)
					err := f.master.Do(t.Context(), func(ctx context.Context) error {
						return f.master.Options.Update(ctx, map[string]any{"scripts": []string{"one", "one"}})
					})
					if err == nil || err.Error() != "Duplicate script" {
						t.Fatalf("duplicate diagnostic=%v", err)
					}
				}},
				"test_script_deletion": {func(t *testing.T) {
					f := newFixture(t)
					path := f.file("dummy.star", "\n")
					f.load(path)
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					f.poll()
					if len(f.master.Options.Seq("scripts")) != 0 || len(f.loader.Addons()) != 0 {
						t.Fatal("deleted script remained loaded")
					}
				}},
				"test_order": {func(t *testing.T) {
					f := newFixture(t)
					f.hook(addon.RunningHook{})
					paths := make(map[string]string)
					for _, name := range []string{"a", "b", "c", "e"} {
						paths[name] = f.file(name+".star", "def on_load(loader):\n    ctx.log(\""+name+" load\")\ndef configure(updated):\n    ctx.log(\""+name+" configure\")\ndef running():\n    ctx.log(\""+name+" running\")\ndef done():\n    ctx.log(\""+name+" done\")\n")
					}
					f.load(paths["a"], paths["b"], paths["c"])
					first := lifecycleMessages(f.logs.String())
					want := []string{"a load", "a configure", "a running", "b load", "b configure", "b running", "c load", "c configure", "c running"}
					if diff := gocmp.Diff(want, first); diff != "" {
						t.Fatal(diff)
					}
					f.load(paths["c"], paths["a"], paths["b"])
					second := lifecycleMessages(f.logs.String())
					if diff := gocmp.Diff([]string{"c configure", "a configure", "b configure"}, second[len(first):]); diff != "" {
						t.Fatal(diff)
					}
					f.load(paths["e"], paths["a"])
					third := lifecycleMessages(f.logs.String())
					if diff := gocmp.Diff([]string{"c done", "b done", "a configure", "e load", "e configure", "e running"}, third[len(second):]); diff != "" {
						t.Fatal(diff)
					}
					f.load()
				}},
			}
			for name, test := range tests {
				t.Run(name, test.run)
			}
		})
	})
}

func lifecycleMessages(logs string) []string {
	var out []string
	for line := range strings.SplitSeq(logs, "\n") {
		_, rest, ok := strings.Cut(line, "msg=\"")
		if !ok {
			continue
		}
		text, _, ok := strings.Cut(rest, "\"")
		if !ok {
			continue
		}
		if len(text) > 2 && strings.Contains("abce", text[:1]) && text[1] == ' ' {
			out = append(out, text)
		}
	}
	return out
}
