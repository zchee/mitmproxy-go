// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package keymap

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/master"
)

func TestConsoleKeymap(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]struct{}{"test_binding": {}, "test_bind": {}, "test_join": {}, "test_remove": {}, "test_load_path": {}, "test_parse": {}}
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				k := New(nil)
				switch name {
				case "test_binding":
					if (Binding{Key: "space"}).KeySpec() != " " {
						t.Fatal("space not translated")
					}
				case "test_bind":
					if k.Add(Binding{Key: "foo", Command: "bar", Contexts: []string{"unsupported"}}) == nil {
						t.Fatal("unsupported context accepted")
					}
					mustKeymap(t, k.Add(Binding{Key: "key", Command: "str", Contexts: []string{"options", "commands"}}))
					if _, ok := k.Get("flowlist", "key"); ok {
						t.Fatal("binding leaked to another context")
					}
					if len(k.List("commands")) != 1 {
						t.Fatal("binding missing")
					}
					if _, ok := k.Handle("unknown", "unknown", false); ok {
						t.Fatal("unknown handled")
					}
					if cmd, ok := k.Handle("options", "key", false); !ok || cmd != "str" {
						t.Fatal("local binding missing")
					}
					mustKeymap(t, k.Add(Binding{Key: "glob", Command: "str", Contexts: []string{"global"}}))
					if _, ok := k.Handle("options", "glob", false); !ok {
						t.Fatal("global missing")
					}
					if _, ok := k.Handle("options", "glob", true); ok {
						t.Fatal("handle_only used global")
					}
					for _, key := range []string{"q", "esc"} {
						mustKeymap(t, k.Add(Binding{Key: key, Command: "console.view.pop", Help: "Exit the current view", Contexts: []string{"global"}}))
					}
					help := k.HelpSnapshot()
					if help[len(help)-2].Key != "q" || help[len(help)-1].Key != "esc" {
						t.Fatalf("help snapshot lost registration order: %+v", help)
					}
					if k.Snapshot()[0].Key != "esc" || k.List("all")[0].Key != "esc" {
						t.Fatal("keybindings display lost sorted order")
					}
					help[len(help)-2].Contexts[0] = "changed"
					binding, ok := k.BindingForHelp("Exit the current view")
					if !ok || binding.Key != "q" || binding.Contexts[0] != "global" {
						t.Fatal("help snapshot aliased bindings or changed first-match resolution")
					}
					mustKeymap(t, k.Remove("q", []string{"global"}))
					help = k.HelpSnapshot()
					if help[len(help)-1].Key != "esc" {
						t.Fatal("help snapshot retained a removed binding")
					}
				case "test_join":
					mustKeymap(t, k.Add(Binding{Key: "key", Command: "str", Help: "help1", Contexts: []string{"options"}}))
					mustKeymap(t, k.Add(Binding{Key: "key", Command: "str", Contexts: []string{"commands"}}))
					if len(k.bindings) != 1 || len(k.bindings[0].Contexts) != 2 || k.bindings[0].Help != "help1" {
						t.Fatal("join lost context/help")
					}
					mustKeymap(t, k.Add(Binding{Key: "key", Command: "str", Help: "help2", Contexts: []string{"commands"}}))
					if _, ok := k.BindingForHelp("help1"); ok {
						t.Fatal("stale help cache")
					}
					mustKeymap(t, k.Remove("key", []string{"commands", "options"}))
					if len(k.bindings) != 0 {
						t.Fatal("unbind retained binding")
					}
				case "test_remove":
					mustKeymap(t, k.Add(Binding{Key: "key", Command: "str", Contexts: []string{"options", "commands"}}))
					mustKeymap(t, k.Remove("key", []string{"options"}))
					if diff := cmp.Diff([]string{"commands"}, k.bindings[0].Contexts); diff != "" {
						t.Fatal(diff)
					}
					mustKeymap(t, k.Remove("key", []string{"commands"}))
					if len(k.bindings) != 0 {
						t.Fatal("final binding retained")
					}
				case "test_load_path":
					path := filepath.Join(t.TempDir(), "keys.yaml")
					for _, data := range []string{"\xff\xff\xff", "'''", "- key: key1\n  ctx: [unknown]\n  cmd: foo\n"} {
						mustKeymap(t, os.WriteFile(path, []byte(data), 0o600))
						if _, _, err := ReadPath(path); err == nil {
							t.Fatalf("accepted invalid file %q", data)
						}
					}
					mustKeymap(t, os.WriteFile(path, []byte("- key: key1\n  ctx: [chooser]\n  help: one\n  cmd: >\n    foo bar\n    foo bar\n- key: key2\n  ctx: [flowlist]\n  cmd: foo\n- key: key2\n  ctx: [flowview]\n  cmd: bar\n"), 0o600))
					bindings, present, err := ReadPath(path)
					mustKeymap(t, err)
					if !present {
						t.Fatal("present file missing")
					}
					mustKeymap(t, k.Install(bindings))
					binding, ok := k.Get("chooser", "key1")
					if !ok || binding.Command != "foo bar foo bar\n" {
						t.Fatalf("folded command changed: %+v", binding)
					}
					for _, ctx := range []string{"flowlist", "flowview"} {
						if _, ok := k.Get(ctx, "key2"); !ok {
							t.Fatalf("missing %s", ctx)
						}
					}
				case "test_parse":
					for _, data := range []string{"", "\n\n \n"} {
						bindings, err := Parse([]byte(data))
						mustKeymap(t, err)
						if len(bindings) != 0 {
							t.Fatal("empty input has bindings")
						}
					}
					invalid := map[string]string{"key: val": "expected a list of keys", "val": "expected a list of keys", "- key: key1\n  nonexistent: bar": "Unknown key attributes", "- help: key1": "Missing required key attributes", "- key: key1\n  cmd: [cmd]": "Invalid type for cmd", "- key: key1\n  ctx: foo\n  cmd: cmd": "Invalid type for ctx"}
					for data, want := range invalid {
						_, err := Parse([]byte(data))
						if err == nil || !strings.Contains(err.Error(), want) {
							t.Fatalf("Parse(%q)=%v; want %q", data, err, want)
						}
					}
					bindings, err := Parse([]byte("- key: key1\n  ctx: [one, two]\n  help: one\n  cmd: >\n    foo bar\n    foo bar\n"))
					mustKeymap(t, err)
					want := []Binding{{Key: "key1", Contexts: []string{"one", "two"}, Help: "one", Command: "foo bar foo bar\n"}}
					if diff := cmp.Diff(want, bindings); diff != "" {
						t.Fatal(diff)
					}
				}
			})
		}
	})
	t.Run("config", func(t *testing.T) {
		tests := map[string]struct{}{"default_path": {}, "explicit_load": {}, "errors": {}, "budgets": {}}
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				switch name {
				case "default_path":
					if got := DefaultPath("/config"); got != "/config/keys.yaml" {
						t.Fatal(got)
					}
				case "explicit_load":
					k := NewDefault(nil)
					before := k.Snapshot()
					bindings, err := Parse([]byte("- key: x\n  cmd: foo\n  ctx: [options]\n"))
					mustKeymap(t, err)
					mustKeymap(t, k.Install(bindings))
					if cmd, ok := k.Handle("options", "x", true); !ok || cmd != "foo" {
						t.Fatal("load not installed")
					}
					if cmp.Equal(before, k.Snapshot()) {
						t.Fatal("load made no change")
					}
				case "errors":
					k := NewDefault(nil)
					before := k.Snapshot()
					if k.Install([]Binding{{Key: "x", Contexts: []string{"options"}}, {Key: "y", Contexts: []string{"bad"}}}) == nil {
						t.Fatal("invalid install accepted")
					}
					if diff := cmp.Diff(before, k.Snapshot()); diff != "" {
						t.Fatal("failed load partially installed: " + diff)
					}
					if _, present, err := ReadPath(filepath.Join(t.TempDir(), "missing")); present || err != nil {
						t.Fatal("missing file is not a no-op")
					}
					if _, present, err := ReadPath(t.TempDir()); present || err != nil {
						t.Fatal("directory is not a no-op")
					}
				case "budgets":
					inputs := []string{strings.Repeat(" ", MaxInputBytes+1), strings.Repeat("[", 33) + strings.Repeat("]", 33), strings.Repeat("- {key: x, cmd: y}\n", maxBindings+1), "- &a [*a]", "- *undefined"}
					for _, data := range inputs {
						if _, err := Parse([]byte(data)); err == nil {
							t.Fatalf("accepted budget/alias failure with %d bytes", len(data))
						}
					}
					// Expanded aliases exceed the node budget despite a small input graph.
					bomb := "- &a [x, x, x, x, x, x, x, x, x, x]\n"
					prev := "a"
					for _, next := range []string{"b", "c", "d", "e", "f"} {
						bomb += "- &" + next + " [" + strings.TrimSuffix(strings.Repeat("*"+prev+",", 10), ",") + "]\n"
						prev = next
					}
					if _, err := Parse([]byte(bomb)); err == nil {
						t.Fatal("expanded alias budget accepted")
					}
				}
			})
		}
	})
	t.Run("registration", func(t *testing.T) {
		t.Run("keymap_load", func(t *testing.T) {
			m := master.New(master.Config{})
			t.Cleanup(func() { mustKeymap(t, m.Close(context.WithoutCancel(t.Context()))) })
			var path string
			mustKeymap(t, m.Addons.Add(t.Context(), &Config{Submit: func(_ context.Context, value string) error { path = value; return nil }}))
			_, err := m.Call(t.Context(), "console.keymap.load", command.Path("/keys.yaml"))
			mustKeymap(t, err)
			if path != "/keys.yaml" {
				t.Fatalf("wrong load path %q", path)
			}
		})
	})
}

func mustKeymap(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func FuzzConsoleKeysYAML(f *testing.F) {
	for _, seed := range []string{"", "- key: a\n  cmd: console.exit\n", "- &a [*a]", "- key: 日\n  ctx: [options]\n  cmd: >\n    x\n    y\n"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxInputBytes+1 {
			return
		}
		bindings, err := Parse(data)
		if err != nil {
			return
		}
		for _, b := range bindings {
			if b.Key == "" && b.Command == "" {
				continue
			}
			if len(b.Contexts) > maxNodes {
				t.Fatal("unbounded contexts")
			}
		}
	})
}
