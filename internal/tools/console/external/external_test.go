// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package external

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

func TestMain(m *testing.M) {
	if os.Getenv("MITMPROXY_EDITOR_FIXTURE") == "1" {
		path := os.Args[len(os.Args)-1]
		switch os.Getenv("MITMPROXY_EDITOR_FIXTURE_MODE") {
		case "failure":
			os.Exit(17)
		case "wait":
			if _, err := io.WriteString(os.Stdout, "ready\n"); err != nil {
				os.Exit(3)
			}
			var data [1]byte
			_, _ = os.Stdin.Read(data[:])
			os.Exit(4)
		case "replace":
			if err := os.Remove(path); err != nil {
				os.Exit(3)
			}
			if err := os.Symlink(os.Getenv("MITMPROXY_EDITOR_FIXTURE_TARGET"), path); err != nil {
				os.Exit(3)
			}
		default:
			input, err := os.ReadFile(path)
			if err != nil {
				os.Exit(3)
			}
			if record := os.Getenv("MITMPROXY_EDITOR_FIXTURE_RECORD"); record != "" {
				data, err := json.Marshal(struct {
					Args  []string
					Input []byte
				}{os.Args[1:], input})
				if err != nil {
					os.Exit(3)
				}
				if err := os.WriteFile(record, data, 0o600); err != nil {
					os.Exit(3)
				}
			}
			if os.Getenv("MITMPROXY_EDITOR_FIXTURE_VIEWER") == "" {
				if err := os.WriteFile(path, []byte("edited\n\n"), 0o600); err != nil {
					os.Exit(3)
				}
			}
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func setupEditor(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MITMPROXY_EDITOR_FIXTURE", "1")
	t.Setenv("MITMPROXY_EDITOR_FIXTURE_MODE", "")
	t.Setenv("MITMPROXY_EDITOR_FIXTURE_RECORD", "")
	t.Setenv("MITMPROXY_EDITOR_FIXTURE_VIEWER", "")
	t.Setenv("MITMPROXY_EDITOR", `"`+executable+`"`)
	t.Setenv("EDITOR", "")
	t.Setenv("PAGER", "")
	t.Setenv("PATH", t.TempDir())
	return executable
}

func processRun(t *testing.T, request Request) (*Process, Result) {
	t.Helper()
	p, err := Prepare(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p, p.Complete(p.Command.Run())
}

func editFixture(t *testing.T) *flow.HTTPFlow {
	t.Helper()
	request, err := httpmsg.MakeRequest("POST", "https://example.test/", []byte("original"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f := flow.NewHTTPFlow(connection.NewClient(connection.Address{}, connection.Address{}, 1), connection.NewServer(nil), false)
	f.Request = request
	return f
}

type processModel struct {
	process *Process
	result  *Result
}

func (m *processModel) Init() tea.Cmd {
	return m.process.Tea(func(result Result) tea.Msg { return result })
}

func (m *processModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if result, ok := msg.(Result); ok {
		m.result = &result
		return m, tea.Quit
	}
	return m, nil
}

func (m *processModel) View() tea.View {
	view := tea.NewView("editor lifecycle")
	view.AltScreen = true
	return view
}

func TestConsoleEditor(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"test_spawn_editor": {func(t *testing.T) {
				setupEditor(t)
				for _, data := range [][]byte{[]byte("text"), {0, 1, 2, 3, 4, 5}} {
					_, result := processRun(t, Request{Data: data})
					if result.Err != nil || string(result.Data) != "edited\n\n" {
						t.Fatalf("data=%x result=%+v", data, result)
					}
				}
			}},
			"test_get_hex_editor": {func(t *testing.T) {
				executable := setupEditor(t)
				name := filepath.Join(os.Getenv("PATH"), "hexedit")
				if err := os.Symlink(executable, name); err != nil {
					t.Fatal(err)
				}
				command, err := Resolve([]byte{0, 1, 2, 3}, false)
				if err != nil || filepath.Base(command) != "hexedit" {
					t.Fatalf("command=%q err=%v", command, err)
				}
			}},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
	t.Run("process", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"editor_precedence": {func(t *testing.T) {
				executable := setupEditor(t)
				t.Setenv("EDITOR", "other")
				command, err := Resolve([]byte("text"), false)
				if err != nil || command != `"`+executable+`"` {
					t.Fatalf("command=%q err=%v", command, err)
				}
				t.Setenv("MITMPROXY_EDITOR", "")
				command, err = Resolve([]byte("text"), false)
				if err != nil || command != "other" {
					t.Fatalf("command=%q err=%v", command, err)
				}
			}},
			"viewer_precedence": {func(t *testing.T) {
				executable := setupEditor(t)
				t.Setenv("MITMPROXY_EDITOR", "")
				t.Setenv("PAGER", "pager")
				t.Setenv("EDITOR", "editor")
				command, err := Resolve(nil, true)
				if err != nil || command != "pager" {
					t.Fatal(command, err)
				}
				t.Setenv("PAGER", "")
				command, _ = Resolve(nil, true)
				if command != "editor" {
					t.Fatal(command)
				}
				t.Setenv("EDITOR", "")
				command, _ = Resolve(nil, true)
				if command != "less" {
					t.Fatal(command)
				}
				t.Setenv("MITMPROXY_EDITOR", fmt.Sprintf("%q", executable))
				t.Setenv("MITMPROXY_EDITOR_FIXTURE_VIEWER", "1")
				p, err := Prepare(t.Context(), Request{Data: []byte("read only"), Viewer: true, ContentType: "text/plain"})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = p.Close() })
				info, err := os.Stat(filepath.Join(p.directory, p.name))
				if err != nil || info.Mode().Perm() != 0o400 {
					t.Fatal("viewer payload is not read-only", err)
				}
				result := p.Complete(p.Command.Run())
				if result.Err != nil || string(result.Data) != "read only" {
					t.Fatalf("viewer result: %+v", result)
				}
			}},
			"argv_only": {func(t *testing.T) {
				executable := setupEditor(t)
				record := filepath.Join(t.TempDir(), "record.json")
				t.Setenv("MITMPROXY_EDITOR_FIXTURE_RECORD", record)
				t.Setenv("MITMPROXY_EDITOR", fmt.Sprintf("%q 'two words' \"$HOME\" ';touch marker'", executable))
				p, result := processRun(t, Request{Data: []byte("input")})
				if result.Err != nil {
					t.Fatal(result.Err)
				}
				data, err := os.ReadFile(record)
				if err != nil {
					t.Fatal(err)
				}
				var got struct {
					Args  []string
					Input []byte
				}
				if err := json.Unmarshal(data, &got); err != nil {
					t.Fatal(err)
				}
				want := []string{"two words", "$HOME", ";touch marker", filepath.Join(p.directory, p.name)}
				if diff := gocmp.Diff(want, got.Args); diff != "" {
					t.Fatal(diff)
				}
				if !bytes.Equal(got.Input, []byte("input")) {
					t.Fatal("input changed")
				}
			}},
			"nonzero_exit": {func(t *testing.T) {
				setupEditor(t)
				t.Setenv("MITMPROXY_EDITOR_FIXTURE_MODE", "failure")
				_, result := processRun(t, Request{Data: []byte("input")})
				if result.Err == nil || result.Data != nil {
					t.Fatalf("result=%+v", result)
				}
			}},
			"temp_cleanup": {func(t *testing.T) {
				setupEditor(t)
				p, result := processRun(t, Request{Data: []byte("input")})
				if result.Err != nil {
					t.Fatal(result.Err)
				}
				if _, err := os.Stat(p.directory); !os.IsNotExist(err) {
					t.Fatalf("directory remains: %v", err)
				}
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("must stay"), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("MITMPROXY_EDITOR_FIXTURE_MODE", "replace")
				t.Setenv("MITMPROXY_EDITOR_FIXTURE_TARGET", target)
				_, result = processRun(t, Request{})
				if result.Err == nil {
					t.Fatal("accepted symlink")
				}
				data, err := os.ReadFile(target)
				if err != nil || string(data) != "must stay" {
					t.Fatal("target changed", err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				abandoned, err := Prepare(ctx, Request{Data: []byte("discarded result")})
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				cancel()
				select {
				case <-abandoned.cleaned:
				case <-time.After(10 * time.Second):
					t.Fatal("discarded prepared process did not clean up")
				}
				if _, err := os.Stat(abandoned.directory); !os.IsNotExist(err) || abandoned.Command.Process != nil {
					t.Fatal("discarded result leaked a process or file", err)
				}
			}},
			"cancel_restore": {func(t *testing.T) {
				setupEditor(t)
				t.Setenv("MITMPROXY_EDITOR_FIXTURE_MODE", "wait")
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				p, err := Prepare(ctx, Request{Data: []byte("input")})
				if err != nil {
					t.Fatal(err)
				}
				stdin, writer, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := stdin.Close(); err != nil {
						t.Error(err)
					}
					if err := writer.Close(); err != nil {
						t.Error(err)
					}
				}()
				p.Command.Stdin = stdin
				stdout, err := p.Command.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				if err := p.Command.Start(); err != nil {
					t.Fatal(err)
				}
				ready := make([]byte, 6)
				if _, err := io.ReadFull(stdout, ready); err != nil || string(ready) != "ready\n" {
					t.Fatal("child not ready", err)
				}
				cancel()
				result := p.Complete(p.Command.Wait())
				if result.Err == nil || p.Command.ProcessState == nil {
					t.Fatal("child not reaped")
				}
				if _, err := os.Stat(p.directory); !os.IsNotExist(err) {
					t.Fatal("temporary directory remains")
				}
				for _, mode := range []string{"", "failure"} {
					t.Setenv("MITMPROXY_EDITOR_FIXTURE_MODE", mode)
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					process, err := Prepare(ctx, Request{Data: []byte("input")})
					if err != nil {
						cancel()
						t.Fatal(err)
					}
					var output bytes.Buffer
					model := &processModel{process: process}
					_, err = tea.NewProgram(model, tea.WithContext(ctx), tea.WithInput(nil), tea.WithOutput(&output), tea.WithWindowSize(80, 24), tea.WithEnvironment([]string{"TERM=xterm-256color"}), tea.WithoutSignalHandler()).Run()
					cancel()
					if err != nil || model.result == nil || (model.result.Err != nil) != (mode == "failure") {
						t.Fatalf("mode=%q program=%v result=%+v", mode, err, model.result)
					}
					if strings.Count(output.String(), "\x1b[?1049h") < 2 || strings.Count(output.String(), "\x1b[?1049l") < 2 {
						t.Fatalf("mode=%q terminal not released/restored: %q", mode, output.String())
					}
					if process.Command.ProcessState == nil || !process.Command.ProcessState.Exited() {
						t.Fatal("process was not joined")
					}
				}
			}},
			"stale_target": {func(t *testing.T) {
				f := editFixture(t)
				s, err := Capture(f, "request-body", contract.DetailOptions{})
				if err != nil {
					t.Fatal(err)
				}
				f.Request.RawContent = []byte("new hook content")
				hash, err := Fingerprint(f, s.Target)
				if err != nil {
					t.Fatal(err)
				}
				if hash == s.Target.Fingerprint {
					t.Fatal("changed target accepted")
				}
				if string(f.Request.RawContent) != "new hook content" {
					t.Fatal("live changed")
				}
				f.Request.RawContent = []byte("original")
				f.Comment = "unrelated"
				hash, err = Fingerprint(f, s.Target)
				if err != nil || hash != s.Target.Fingerprint {
					t.Fatal("unrelated change conflicts", err)
				}
				urlSession, err := Capture(f, "url", contract.DetailOptions{})
				if err != nil {
					t.Fatal(err)
				}
				f.Request.Headers.Set("x-changed", "new hook value")
				hash, err = Fingerprint(f, urlSession.Target)
				if err != nil || hash == urlSession.Target.Fingerprint {
					t.Fatal("URL edit would overwrite changed headers", err)
				}
			}},
			"strip_newlines": {func(t *testing.T) {
				for _, part := range []string{"request-body", "response-body", "url", "tcp-message", "udp-message", "websocket-message"} {
					for _, enabled := range []bool{false, true} {
						got := StripNewlines([]byte{0xff, 'x', '\n', '\n'}, part, enabled)
						strip := enabled || part == "url" || strings.HasSuffix(part, "-message")
						want := []byte{0xff, 'x', '\n', '\n'}
						if strip {
							want = []byte{0xff, 'x'}
						}
						if diff := gocmp.Diff(want, got); diff != "" {
							t.Fatal(part, enabled, diff)
						}
					}
				}
			}},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}

func FuzzConsoleEditorArgv(f *testing.F) {
	for _, seed := range []string{"vi", `vim -f "two words"`, `editor '' '$HOME'`, "trailing\\", "unclosed'", "", "editor --wait", `editor --title "two words"`, "'editor path' --wait", `editor "unterminated`, "editor '$HOME;echo literal'", "editor\x00argument", "editor --title 日本語"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		args, err := ParseArgv(input)
		if err != nil {
			return
		}
		if len(args) == 0 || args[0] == "" {
			t.Fatal("empty accepted command")
		}
		for _, arg := range args {
			if strings.ContainsRune(arg, 0) {
				t.Fatal("NUL accepted")
			}
		}
	})
}
