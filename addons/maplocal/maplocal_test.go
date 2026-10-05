// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package maplocal

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/filter/regex"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/internal/version"
	"github.com/zchee/mitmproxy-go/options"
)

func setup(t *testing.T, patterns []string) (*addon.Manager, *options.Manager, *MapLocal) {
	t.Helper()
	opts := options.New()
	mgr := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(mgr.Close)
	m := New(opts)
	if err := mgr.Add(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"map_local": patterns}) }); err != nil {
		t.Fatal(err)
	}
	return mgr, opts, m
}

// TestFileCandidates ports every vector in upstream test_file_candidates.
func TestFileCandidates(t *testing.T) {
	root := t.TempDir()
	tests := map[string]struct {
		url, pattern string
		want         []string
	}{
		"success: exact prefix":                   {"https://example.com/foo", "example.com/foo", []string{"index.html"}},
		"success: trailing slash":                 {"https://example.com/foo/", "example.com/foo", []string{"index.html"}},
		"success: root slash":                     {"https://example.com/foo", "example.com/foo", []string{"index.html"}},
		"success: http prefix":                    {"http://example.com/foo/bar.jpg", "example.com/foo", []string{"bar.jpg", "bar.jpg/index.html"}},
		"success: https prefix":                   {"https://example.com/foo/bar.jpg", "example.com/foo", []string{"bar.jpg", "bar.jpg/index.html"}},
		"success: discard query":                  {"https://example.com/foo/bar.jpg?query", "example.com/foo", []string{"bar.jpg", "bar.jpg/index.html"}},
		"success: nested prefix":                  {"https://example.com/foo/bar/baz.jpg", "example.com/foo", []string{"bar/baz.jpg", "bar/baz.jpg/index.html"}},
		"success: full match":                     {"https://example.com/foo/bar.jpg", "/foo/bar.jpg", []string{"index.html"}},
		"success: percent decode":                 {"http://example.com/foo%20bar.jpg", "example.com", []string{"foo bar.jpg", "foo bar.jpg/index.html", "foo_bar.jpg", "foo_bar.jpg/index.html"}},
		"success: Unicode":                        {"http://example.com/fóobår.jpg", "example.com", []string{"fóobår.jpg", "fóobår.jpg/index.html", "f_ob_r.jpg", "f_ob_r.jpg/index.html"}},
		"success: index exact":                    {"https://example.com/foo", "example.com/foo", []string{"index.html"}},
		"success: index trailing":                 {"https://example.com/foo/", "example.com/foo", []string{"index.html"}},
		"success: directory fallback":             {"https://example.com/foo/bar", "example.com/foo", []string{"bar", "bar/index.html"}},
		"success: directory slash fallback":       {"https://example.com/foo/bar/", "example.com/foo", []string{"bar", "bar/index.html"}},
		"success: captured suffix":                {"https://example/view.php?f=foo.jpg", `example/view.php\?f=(.+)`, []string{"foo.jpg", "foo.jpg/index.html"}},
		"success: captured query":                 {"https://example/results?id=1&foo=2", `example/(results\?id=.+)`, []string{"results?id=1&foo=2", "results?id=1&foo=2/index.html", "results_id=1_foo=2", "results_id=1_foo=2/index.html"}},
		"skip: traversal":                         {"https://example.com/../../../../../../etc/passwd", "example.com", nil},
		"success: doubled slash":                  {"https://example.com//etc/passwd", "example.com", []string{"etc/passwd", "etc/passwd/index.html"}},
		"skip: encoded traversal":                 {"https://example.com/%2e%2e/secret", "example.com", nil},
		"skip: embedded traversal":                {"https://example.com/a/../secret", "example.com", nil},
		"skip: decoded absolute suffix":           {"https://example.com/%2Fetc/passwd", "example.com", nil},
		"skip: captured absolute suffix":          {"https://example.com/etc/passwd", `example.com(/etc/passwd)`, nil},
		"success: malformed escape stays literal": {"https://example.com/foo%ZZ", "example.com", []string{"foo%ZZ", "foo%ZZ/index.html", "foo_ZZ", "foo_ZZ/index.html"}},
		"success: plus is literal":                {"https://example.com/foo+bar", "example.com", []string{"foo+bar", "foo+bar/index.html", "foo_bar", "foo_bar/index.html"}},
	}
	windowsWant := []string{"C:\\foo.txt", "C:\\foo.txt/index.html", "C__foo.txt", "C__foo.txt/index.html"}
	if runtime.GOOS == "windows" {
		windowsWant = nil
	}
	tests["platform: drive path"] = struct {
		url, pattern string
		want         []string
	}{"https://example.com/C:\\foo.txt", "example.com", windowsWant}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := regex.CompilePattern(test.pattern, regex.Unicode)
			if err != nil {
				t.Fatal(err)
			}
			dir := root
			if name == "success: root slash" {
				dir += string(filepath.Separator)
			}
			got, err := fileCandidates(test.url, mapping{pattern: p, localPath: dir})
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			for _, path := range test.want {
				want = append(want, filepath.Join(root, filepath.FromSlash(path)))
			}
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// TestConfigure ports upstream TestMapLocal.test_configure.
func TestConfigure(t *testing.T) {
	root := t.TempDir()
	mgr, opts, _ := setup(t, []string{"/foo/bar/" + root})
	tests := map[string]struct{ pattern, message string }{
		"error: pattern":    {"/foo/+/" + root, "Invalid regular expression '+'"},
		"error: path":       {"/foo/.+/" + filepath.Join(root, "missing"), "Invalid file path:"},
		"error: incomplete": {"/", "Invalid number of parameters"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := mgr.Do(t.Context(), func(ctx context.Context) error {
				return opts.Update(ctx, map[string]any{"map_local": []string{test.pattern}})
			})
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("configure=%v, want %q", err, test.message)
			}
			if diff := gocmp.Diff([]string{"/foo/bar/" + root}, opts.Seq("map_local")); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func writeFile(t *testing.T, root, name, contents string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRequest ports test_simple and every map_local feature example.
func TestRequest(t *testing.T) {
	tests := map[string]struct {
		pattern, url, path, method, wantType string
		file                                 bool
	}{
		"success: directory":         {"|//example.org/images|", "https://example.org/images/foo.jpg", "foo.jpg", "", "image/jpeg", false},
		"success: nested directory":  {"|//example.org|", "https://example.org/images/bar.jpg", "images/bar.jpg", "", "image/jpeg", false},
		"success: direct file":       {"|example.org/foo/foo/bar.jpg|", "https://example.org/foo/foo/bar.jpg", "foofoobar.jpg", "", "image/jpeg", true},
		"success: fallback index":    {"|example.org/css|", "https://example.org/css/main", "main/index.html", "", "text/html", false},
		"success: escaped fallback":  {"|example.org|", "https://example.org/foo%20bar.jpg", "foo_bar.jpg", "", "image/jpeg", false},
		"success: unknown extension": {"|example.org|", "https://example.org/main.unknownextension", "main.unknownextension", "", "", false},
		"docs: javascript file":      {"|example.com/main.js|", "https://example.com/main.js", "main-local.js", "", "text/javascript", true},
		"docs: static directory":     {"|example.com/static|", "https://example.com/static/foo/bar.css", "foo/bar.css", "", "text/css", false},
		"docs: longer prefix":        {"|example.com/static/foo|", "https://example.com/static/foo/bar.css", "bar.css", "", "text/css", false},
		"docs: method filter":        {"|~m GET|example.com/static|", "https://example.com/static/foo/bar.css", "foo/bar.css", "GET", "text/css", false},
		"docs: query stripped":       {"|example.com/css|", "https://example.com/css/print/main.css?timestamp=123", "print/main.css", "", "text/css", false},
		"docs: query capture":        {"|~m GET|example.com/index.php\\?page=(.+)|", "https://example.com/index.php?page=aboutus", "aboutus", "GET", "", false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			file := writeFile(t, root, test.path, "served bytes")
			target := root
			if test.file {
				target = file
			}
			mgr, _, _ := setup(t, []string{test.pattern + target})
			f := testflow.TFlow()
			if err := f.Request.SetURL(test.url); err != nil {
				t.Fatal(err)
			}
			if test.method != "" {
				f.Request.Method = test.method
			}
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if f.Response == nil {
				t.Fatal("missing response")
			}
			gotType, _, _ := strings.Cut(f.Response.Headers.Get("Content-Type"), ";")
			if diff := gocmp.Diff([]any{200, "served bytes", test.wantType, version.String()}, []any{f.Response.StatusCode, string(f.Response.ContentOrRaw()), gotType, f.Response.Headers.Get("Server")}); diff != "" {
				t.Fatal(diff)
			}
			// Local changes take effect without reconfiguration.
			if err := os.WriteFile(file, []byte("updated"), 0o600); err != nil {
				t.Fatal(err)
			}
			f.Response = nil
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff("updated", string(f.Response.ContentOrRaw())); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	t.Run("docs: home path", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		writeFile(t, home, "main-local.js", "home file")
		mgr, _, _ := setup(t, []string{"|example.com/main.js|~/main-local.js"})
		f := testflow.TFlow()
		if err := f.Request.SetURL("https://example.com/main.js"); err != nil {
			t.Fatal(err)
		}
		if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
			t.Fatal(err)
		}
		if diff := gocmp.Diff("home file", string(f.Response.ContentOrRaw())); diff != "" {
			t.Fatal(diff)
		}
	})
}

// TestNonexistentFiles ports test_nonexistent_files with real files, not a patched Path.is_file.
// The upstream read-failure monkeypatch is replaced by an oversized regular file
// below, which exercises the same warning and continuation path deterministically.
func TestNonexistentFiles(t *testing.T) {
	root := t.TempDir()
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	mgr, _, _ := setup(t, []string{"|example.org/css|" + root})
	f := testflow.TFlow()
	if err := f.Request.SetURL("https://example.org/css/nonexistent"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if f.Response == nil || f.Response.StatusCode != 404 {
		t.Fatal("missing 404")
	}
	if !strings.Contains(logs.String(), "None of the local file candidates exist:") {
		t.Fatal(logs.String())
	}
	file := writeFile(t, root, "large", "x")
	handle, err := os.OpenFile(file, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Truncate(maxFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	mgr, _, _ = setup(t, []string{"|address|" + file, "|address|" + writeFile(t, root, "fallback", "ok")})
	f = testflow.TFlow()
	if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff("ok", string(f.Response.ContentOrRaw())); diff != "" {
		t.Fatal(diff)
	}
	if !strings.Contains(logs.String(), "Could not read file:") {
		t.Fatal(logs.String())
	}
}

// TestTaken ports test_is_killed and distinguishes rejected candidates from 404.
func TestTaken(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "foo.jpg", "foo")
	tests := map[string]struct {
		url    string
		mutate func(*flow.HTTPFlow)
		status int
	}{
		"skip: killed": {url: "https://example.org/foo.jpg", mutate: func(f *flow.HTTPFlow) {
			if err := f.Kill(); err != nil {
				t.Fatal(err)
			}
		}},
		"skip: failed":                           {url: "https://example.org/foo.jpg", mutate: func(f *flow.HTTPFlow) { f.Error = flow.NewError("failed") }},
		"skip: inactive":                         {url: "https://example.org/foo.jpg", mutate: func(f *flow.HTTPFlow) { f.Live = false }},
		"skip: answered":                         {url: "https://example.org/foo.jpg", mutate: func(f *flow.HTTPFlow) { f.Response = testflow.TResp() }, status: 200},
		"skip: no pattern match":                 {url: "https://other.org/foo.jpg"},
		"skip: traversal no candidates":          {url: "https://example.org/../foo.jpg"},
		"success: missing candidates return 404": {url: "https://example.org/missing", status: 404},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, _, _ := setup(t, []string{"|example.org|" + root})
			f := testflow.TFlow()
			if err := f.Request.SetURL(test.url); err != nil {
				t.Fatal(err)
			}
			if test.mutate != nil {
				test.mutate(f)
			}
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			got := 0
			if f.Response != nil {
				got = f.Response.StatusCode
			}
			if diff := gocmp.Diff(test.status, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestRootedFiles(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	file := writeFile(t, outside, "secret", "outside")
	inside := writeFile(t, root, "inside", "inside")
	if err := os.Symlink(file, filepath.Join(root, "outside")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(inside), filepath.Join(root, "relative")); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		path, want string
		status     int
	}{"skip: external symlink": {"outside", "", 404}, "success: relative internal symlink": {"relative", "inside", 200}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, _, _ := setup(t, []string{"|example.org|" + root})
			f := testflow.TFlow()
			if err := f.Request.SetURL("https://example.org/" + test.path); err != nil {
				t.Fatal(err)
			}
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if f.Response == nil {
				t.Fatal("missing response")
			}
			if diff := gocmp.Diff([]any{test.status, test.want}, []any{f.Response.StatusCode, string(f.Response.ContentOrRaw())}); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestOptionsAndCommands(t *testing.T) {
	opts := options.New()
	cmds := command.NewManager()
	mgr := addon.NewManager(opts, cmds, addon.Config{})
	t.Cleanup(mgr.Close)
	m := New(opts)
	if err := mgr.Add(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		typ  options.Type
		def  any
		help string
	}{"map_local": {options.TypeSeq, []string{}, `Map remote resources to a local file using a pattern of the form "[/flow-filter]/url-regex/file-or-directory-path", where the separator can be any character.`}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			o, ok := opts.Lookup(name)
			if !ok {
				t.Fatal("missing option")
			}
			if diff := gocmp.Diff([]any{test.typ, test.def, test.help}, []any{o.Type(), o.Default(), o.Help()}); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	for name := range cmds.Commands() {
		t.Errorf("unexpected command %s; upstream declares none", name)
	}
	if m.Name() != "maplocal" {
		t.Fatal(m.Name())
	}
}

func TestConcurrentDispatch(t *testing.T) {
	root := t.TempDir()
	file := writeFile(t, root, "file", "body")
	mgr, _, _ := setup(t, []string{"|address|" + file})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 16 {
				f := testflow.TFlow()
				if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
					t.Error(err)
				}
				if f.Response == nil || string(f.Response.ContentOrRaw()) != "body" {
					t.Error("file not served")
				}
			}
		})
	}
	wg.Wait()
}
