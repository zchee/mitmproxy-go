// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package commandhistory

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/options"
)

func setup(t *testing.T, dir string) (*Addon, *addon.Manager, *command.Manager, *options.Manager) {
	t.Helper()
	opts := options.New()
	if err := opts.Update(t.Context(), map[string]any{"confdir": dir}); err != nil {
		t.Fatal(err)
	}
	cmds := command.NewManager()
	m := addon.NewManager(opts, cmds, addon.Config{})
	t.Cleanup(m.Close)
	a := New(opts)
	if err := m.Add(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	return a, m, cmds, opts
}

func call(t *testing.T, cmds *command.Manager, name string, args ...any) any {
	t.Helper()
	result, err := cmds.Call(t.Context(), "commands.history."+name, args...)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func history(t *testing.T, cmds *command.Manager, want []string) {
	t.Helper()
	got := call(t, cmds, "get")
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}
}

func nativeText(text string) string {
	if runtime.GOOS == "windows" {
		return strings.ReplaceAll(text, "\n", "\r\n")
	}
	return text
}

// TestPersistence ports test_load_and_save and checks odd vacuum sizes and running reloads.
func TestPersistence(t *testing.T) {
	tests := map[string]struct {
		size int
		want string
	}{
		"even": {4, "cmd3\ncmd4\n"},
		"odd":  {3, "cmd3\ncmd4\n"},
		"one":  {1, "cmd4\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "command_history")
			if err := os.WriteFile(path, []byte("cmd1\ncmd2\ncmd3"), 0o600); err != nil {
				t.Fatal(err)
			}
			a, m, cmds, opts := setup(t, t.TempDir())
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				a.vacuumSize = tt.size
				return opts.Update(ctx, map[string]any{"confdir": dir})
			}); err != nil {
				t.Fatal(err)
			}
			history(t, cmds, []string{"cmd1", "cmd2", "cmd3"})
			call(t, cmds, "add", "cmd4")
			if err := m.Trigger(t.Context(), addon.DoneHook{}); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(nativeText(tt.want), string(data)); diff != "" {
				t.Fatal(diff)
			}
			history(t, cmds, []string{"cmd1", "cmd2", "cmd3", "cmd4"})
			if err := m.Trigger(t.Context(), addon.RunningHook{}); err != nil {
				t.Fatal(err)
			}
			history(t, cmds, strings.Split(strings.TrimSuffix(tt.want, "\n"), "\n"))
		})
	}
}

// TestAdd ports test_add_command, including Python whitespace and copy isolation.
func TestAdd(t *testing.T) {
	_, _, cmds, _ := setup(t, t.TempDir())
	call(t, cmds, "add", "cmd1")
	call(t, cmds, "add", "cmd2")
	tests := map[string]struct{ text string }{
		"empty": {""}, "ASCII": {" \t\r\n"}, "Unicode": {"    "}, "Python separators": {"\x1c\x1d\x1e\x1f"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) { call(t, cmds, "add", tt.text); history(t, cmds, []string{"cmd1", "cmd2"}) })
	}
	copy := call(t, cmds, "get").([]string)
	copy[0] = "changed"
	history(t, cmds, []string{"cmd1", "cmd2"})
	call(t, cmds, "add", "  untrimmed  ")
	history(t, cmds, []string{"cmd1", "cmd2", "  untrimmed  "})
}

// TestNavigation ports every sequence in test_get_next_and_prev and test_filter.
func TestNavigation(t *testing.T) {
	tests := map[string]struct {
		additions   []string
		prefix      *string
		moves, want []string
	}{
		"one":           {[]string{"cmd1"}, nil, strings.Fields("next next prev prev prev next next"), []string{"", "", "cmd1", "cmd1", "cmd1", "", ""}},
		"two":           {[]string{"cmd1", "cmd2"}, nil, strings.Fields("next next prev prev prev next next next"), []string{"", "", "cmd2", "cmd1", "cmd1", "cmd2", "", ""}},
		"three":         {[]string{"cmd1", "cmd2", "cmd3"}, nil, strings.Fields("next next prev prev prev prev next next next next prev prev"), []string{"", "", "cmd3", "cmd2", "cmd1", "cmd1", "cmd2", "cmd3", "", "", "cmd3", "cmd2"}},
		"four":          {[]string{"cmd1", "cmd2", "cmd3", "cmd4"}, nil, strings.Fields("prev prev prev prev prev next next next next next"), []string{"cmd4", "cmd3", "cmd2", "cmd1", "cmd1", "cmd2", "cmd3", "cmd4", "", ""}},
		"six":           {[]string{"cmd1", "cmd2", "cmd3", "cmd4", "cmd5", "cmd6"}, nil, strings.Fields("next prev prev prev next prev prev prev next prev prev prev prev next next next next next next next"), []string{"", "cmd6", "cmd5", "cmd4", "cmd5", "cmd4", "cmd3", "cmd2", "cmd3", "cmd2", "cmd1", "cmd1", "cmd1", "cmd2", "cmd3", "cmd4", "cmd5", "cmd6", "", ""}},
		"filter":        {[]string{"cmd1", "cmd2", "abc"}, new("c"), strings.Fields("next next prev prev prev next next next"), []string{"c", "c", "cmd2", "cmd1", "cmd1", "cmd2", "c", "c"}},
		"reset filter":  {[]string{"cmd1", "cmd2", "abc"}, new(""), strings.Fields("next next prev prev prev prev next next next next"), []string{"", "", "abc", "cmd2", "cmd1", "cmd1", "cmd2", "abc", "", ""}},
		"empty matches": {[]string{"cmd1"}, new("absent"), strings.Fields("prev next prev"), []string{"absent", "absent", "absent"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, cmds, _ := setup(t, t.TempDir())
			for _, text := range tt.additions {
				call(t, cmds, "add", text)
			}
			if tt.prefix != nil {
				call(t, cmds, "filter", *tt.prefix)
			}
			var got []string
			for _, move := range tt.moves {
				got = append(got, call(t, cmds, move).(string))
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
			call(t, cmds, "filter", "absent")
			call(t, cmds, "add", "new")
			if got := call(t, cmds, "prev"); got != "new" {
				t.Fatalf("reset=%v", got)
			}
		})
	}
}

// TestClear ports test_clear, including deletion when persistence is disabled.
func TestClear(t *testing.T) {
	dir := t.TempDir()
	_, m, cmds, opts := setup(t, dir)
	call(t, cmds, "add", "cmd1")
	call(t, cmds, "add", "cmd2")
	if err := m.Do(t.Context(), func(ctx context.Context) error { return opts.Set(ctx, "command_history=false") }); err != nil {
		t.Fatal(err)
	}
	call(t, cmds, "clear")
	history(t, cmds, []string{})
	for _, name := range []string{"next", "next", "prev", "prev"} {
		if got := call(t, cmds, name); got != "" {
			t.Fatalf("%s=%v", name, got)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "command_history")); !os.IsNotExist(err) {
		t.Fatalf("file retained: %v", err)
	}
	call(t, cmds, "clear")
	call(t, cmds, "add", "not persisted")
	history(t, cmds, []string{"not persisted"})
	if _, err := os.Stat(filepath.Join(dir, "command_history")); !os.IsNotExist(err) {
		t.Fatalf("disabled persistence: %v", err)
	}
}

// TestFailures ports test_done_writing_failed, test_add_command_failed and test_clear_failed with real filesystem failures.
func TestFailures(t *testing.T) {
	tests := map[string]struct{ failure string }{
		"missing parent": {"missing"}, "directory": {"directory"}, "empty directory": {"empty directory"}, "permission": {"permission"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "command_history")
			switch tt.failure {
			case "missing":
				dir = filepath.Join(dir, "absent")
				path = filepath.Join(dir, "command_history")
			case "directory", "empty directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if tt.failure == "directory" {
					if err := os.WriteFile(filepath.Join(path, "child"), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			case "permission":
				if runtime.GOOS == "windows" || os.Geteuid() == 0 {
					t.Skip("POSIX write permissions require a non-root user")
				}
				if err := os.WriteFile(path, nil, 0o400); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
						t.Error(err)
					}
				})
			}
			loggedPath := path
			if runtime.GOOS == "windows" {
				// TextHandler escapes backslashes inside its quoted message field.
				loggedPath = strings.ReplaceAll(path, `\`, `\\`)
			}
			a, m, cmds, _ := setup(t, dir)
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(previous) })
			call(t, cmds, "add", "cmd1")
			history(t, cmds, []string{"cmd1"})
			if !strings.Contains(logs.String(), "Failed writing to "+loggedPath+":") {
				t.Fatalf("append logs=%s", logs.String())
			}
			logs.Reset()
			if err := m.Do(t.Context(), func(context.Context) error { a.vacuumSize = 1; return nil }); err != nil {
				t.Fatal(err)
			}
			if err := m.Trigger(t.Context(), addon.DoneHook{}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(logs.String(), "Failed writing to "+loggedPath+":") {
				t.Fatalf("vacuum logs=%s", logs.String())
			}
			logs.Reset()
			call(t, cmds, "clear")
			history(t, cmds, []string{})
			if strings.Contains(tt.failure, "directory") && !strings.Contains(logs.String(), "Failed deleting "+loggedPath+":") {
				t.Fatalf("clear logs=%s", logs.String())
			}
		})
	}
}

// TestMultipleInstances ports test_multiple_instances without inter-instance state refreshes.
func TestMultipleInstances(t *testing.T) {
	dir := t.TempDir()
	var managers []*addon.Manager
	var commands []*command.Manager
	for range 3 {
		_, m, c, _ := setup(t, dir)
		managers = append(managers, m)
		commands = append(commands, c)
		if err := m.Trigger(t.Context(), addon.RunningHook{}); err != nil {
			t.Fatal(err)
		}
		history(t, c, []string{})
	}
	call(t, commands[0], "add", "cmd1")
	history(t, commands[1], []string{})
	history(t, commands[2], []string{})
	call(t, commands[1], "add", "cmd2")
	history(t, commands[1], []string{"cmd2"})
	history(t, commands[0], []string{"cmd1"})
	call(t, commands[2], "add", "cmd3")
	call(t, commands[0], "add", "cmd4")
	_, m, c, _ := setup(t, dir)
	if err := m.Trigger(t.Context(), addon.RunningHook{}); err != nil {
		t.Fatal(err)
	}
	history(t, c, []string{"cmd1", "cmd2", "cmd3", "cmd4"})
	call(t, commands[0], "add", "cmd_before_close")
	for _, m := range managers {
		if err := m.Trigger(t.Context(), addon.DoneHook{}); err != nil {
			t.Fatal(err)
		}
	}
	history(t, commands[1], []string{"cmd2"})
	call(t, commands[1], "add", "new_cmd")
	data, err := os.ReadFile(filepath.Join(dir, "command_history"))
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(nativeText("cmd1\ncmd2\ncmd3\ncmd4\ncmd_before_close\nnew_cmd\n"), string(data)); diff != "" {
		t.Fatal(diff)
	}
	call(t, c, "clear")
	_, m1, c1, _ := setup(t, dir)
	_, m2, c2, _ := setup(t, dir)
	for _, m := range []*addon.Manager{m1, m2} {
		if err := m.Trigger(t.Context(), addon.RunningHook{}); err != nil {
			t.Fatal(err)
		}
	}
	call(t, c1, "add", "cmd1")
	call(t, c1, "add", "cmd2")
	for _, text := range []string{"cmd3", "cmd4", "cmd5"} {
		call(t, c2, "add", text)
	}
	history(t, c2, []string{"cmd3", "cmd4", "cmd5"})
	for _, m := range []*addon.Manager{m1, m2} {
		if err := m.Trigger(t.Context(), addon.DoneHook{}); err != nil {
			t.Fatal(err)
		}
	}
	data, err = os.ReadFile(filepath.Join(dir, "command_history"))
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(nativeText("cmd1\ncmd2\ncmd3\ncmd4\ncmd5\n"), string(data)); diff != "" {
		t.Fatal(diff)
	}
}

func TestConfigure(t *testing.T) {
	tests := map[string]struct {
		content string
		want    []string
		invalid bool
	}{
		"empty":            {"", []string{}, false},
		"lines":            {"a\r\nb\rc\nd\v\f\x1c\x1d\x1e\u0085  z\n", []string{"a", "b", "c", "d", "", "", "", "", "", "", "", "z"}, false},
		"no final newline": {"first\nlast", []string{"first", "last"}, false},
		"invalid UTF8":     {"\xff", nil, true},
		"oversized":        {strings.Repeat("x", maxHistoryBytes+1), nil, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			a, m, cmds, opts := setup(t, dir)
			if err := os.WriteFile(filepath.Join(dir, "command_history"), []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := m.Do(t.Context(), func(ctx context.Context) error { return opts.Set(ctx, "command_history=false") }); err != nil {
				t.Fatal(err)
			}
			if err := m.InvokeSync(t.Context(), a, addon.ConfigureHook{Updated: map[string]struct{}{"confdir": {}}}); err != nil {
				t.Fatal(err)
			}
			history(t, cmds, []string{})
			if err := m.Do(t.Context(), func(ctx context.Context) error { return opts.Set(ctx, "command_history=true") }); err != nil {
				t.Fatal(err)
			}
			err := m.InvokeSync(t.Context(), a, addon.ConfigureHook{Updated: map[string]struct{}{"command_history": {}}})
			if tt.invalid {
				if err == nil {
					t.Fatal("invalid file accepted")
				}
				history(t, cmds, []string{})
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			history(t, cmds, tt.want)
			if err := os.WriteFile(filepath.Join(dir, "command_history"), []byte("different"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := m.InvokeSync(t.Context(), a, addon.ConfigureHook{Updated: map[string]struct{}{"unrelated": {}}}); err != nil {
				t.Fatal(err)
			}
			history(t, cmds, tt.want)
		})
	}
}

func TestConcurrentCommands(t *testing.T) {
	_, m, cmds, opts := setup(t, t.TempDir())
	if err := m.Do(t.Context(), func(ctx context.Context) error { return opts.Set(ctx, "command_history=false") }); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Go(func() {
			for _, invocation := range []struct {
				name string
				args []any
			}{{"add", []any{fmt.Sprint(i)}}, {"filter", []any{""}}, {"prev", nil}, {"next", nil}, {"get", nil}} {
				if _, err := cmds.Call(t.Context(), "commands.history."+invocation.name, invocation.args...); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	got := call(t, cmds, "get").([]string)
	slices.Sort(got)
	var want []string
	for i := range 64 {
		want = append(want, fmt.Sprint(i))
	}
	slices.Sort(want)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}
}

func TestTables(t *testing.T) {
	a, m, cmds, opts := setup(t, t.TempDir())
	option, ok := opts.Lookup("command_history")
	if !ok || option.Type() != options.TypeBool || option.Default() != true || option.Help() != "Persist command history between mitmproxy invocations." {
		t.Fatalf("option=%v", option)
	}
	tests := map[string]struct {
		signature string
		types     []string
	}{
		"commands.history.add":    {"commands.history.add command", []string{"Str"}},
		"commands.history.get":    {"commands.history.get  -> str[]", nil},
		"commands.history.clear":  {"commands.history.clear ", nil},
		"commands.history.filter": {"commands.history.filter prefix", []string{"Str"}},
		"commands.history.next":   {"commands.history.next  -> str", nil},
		"commands.history.prev":   {"commands.history.prev  -> str", nil},
	}
	for name, c := range cmds.Commands() {
		tt, ok := tests[name]
		if !ok {
			t.Fatalf("unexpected command %s", name)
		}
		if diff := cmp.Diff(tt.signature, c.SignatureHelp()); diff != "" {
			t.Fatal(diff)
		}
		var types []string
		for _, p := range c.Params {
			types = append(types, p.Type.Name())
		}
		if diff := cmp.Diff(tt.types, types); diff != "" {
			t.Fatal(diff)
		}
		delete(tests, name)
	}
	if len(tests) != 0 {
		t.Fatalf("missing commands: %v", tests)
	}
	call(t, cmds, "add", "created")
	info, err := os.Stat(filepath.Join(opts.Str("confdir"), "command_history"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v", info.Mode())
	}
	if err := m.Do(t.Context(), func(context.Context) error {
		if a.vacuumSize != 1024 {
			t.Fatalf("vacuum=%d", a.vacuumSize)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
