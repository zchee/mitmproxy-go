// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package options

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// currentValues returns every option's current value, for comparing two
// managers the way upstream compares OptManager instances.
func currentValues(m *Manager) map[string]any {
	out := make(map[string]any)
	for _, o := range m.Items() {
		out[o.Name()] = o.Current()
	}
	return out
}

func requireOptionsError(t *testing.T, err error, substr string) {
	t.Helper()
	if _, ok := errors.AsType[*OptionsError](err); !ok {
		t.Fatalf("error = %v (%T), want *OptionsError", err, err)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("error = %q, want it to contain %q", err, substr)
	}
}

// TestDump checks the annotated dump byte for byte against the output of
// upstream's dump_defaults for the same options.
func TestDump(t *testing.T) {
	want, err := os.ReadFile("testdata/dump_defaults.yaml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := New().Dump()
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(string(want), got); diff != "" {
		t.Errorf("Dump() mismatch (-upstream +go):\n%s", diff)
	}
}

func TestDumpChoicesAndTypes(t *testing.T) {
	got, err := newTTypes(t).Dump()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"\n# help Valid values are 'foo', 'bar', 'baz'.\nchoices: foo\n",
		"\n# help Type optional int.\noptint: 0\n",
		"\n# help Type sequence of str.\nseqstr: []\n",
		"\n# help Type bool.\nbool_on: true\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Dump() lacks %q; got:\n%s", want, got)
		}
	}
}

// TestSerialize ports test_serialize of mitmproxy's test_optmanager.py.
func TestSerialize(t *testing.T) {
	o := newTD2(t)
	if err := o.Update(t.Context(), map[string]any{"three": "set"}); err != nil {
		t.Fatal(err)
	}
	all, err := o.Serialize("", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(all, "dfour") {
		t.Errorf("Serialize(defaults=true) lacks a default value:\n%s", all)
	}
	data, err := o.Serialize("", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := "three: set\n"; data != want {
		t.Errorf("Serialize(defaults=false) = %q, want %q", data, want)
	}

	o2 := newTD2(t)
	if err := o2.Load(t.Context(), data); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(currentValues(o), currentValues(o2)); diff != "" {
		t.Errorf("Load(Serialize()) mismatch (-want +got):\n%s", diff)
	}

	data, err = o.Serialize("\n    unknown: foo\n", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(data, "unknown") {
		t.Errorf("Serialize kept an unknown key:\n%s", data)
	}
	o2 = newTD2(t)
	if err := o2.Load(t.Context(), data); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(currentValues(o), currentValues(o2)); diff != "" {
		t.Errorf("Load(Serialize(text)) mismatch (-want +got):\n%s", diff)
	}

	requireOptionsError(t, o2.Load(t.Context(), "invalid: foo\ninvalid"), "Config error")
	requireOptionsError(t, o2.Load(t.Context(), "invalid"), "Config error")

	for _, text := range []string{"# a comment", ""} {
		if err := o2.Load(t.Context(), text); err != nil {
			t.Fatalf("Load(%q) = %v", text, err)
		}
		if err := o2.Load(t.Context(), "foobar: '123'"); err != nil {
			t.Fatal(err)
		}
		if diff := gocmp.Diff(map[string]any{"foobar": "123"}, o2.Deferred()); diff != "" {
			t.Errorf("Deferred (-want +got):\n%s", diff)
		}
	}
}

func TestSerializeUpdatesTextInPlace(t *testing.T) {
	o := newTD2(t)
	if err := o.Update(t.Context(), map[string]any{"one": "new"}); err != nil {
		t.Fatal(err)
	}
	got, err := o.Serialize("two: kept\nunknown: x\none: old\n", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := "two: kept\none: new\n"; got != want {
		t.Errorf("Serialize = %q, want %q", got, want)
	}
}

func TestSerializeRoundTripCoreOptions(t *testing.T) {
	m := New()
	if empty, err := m.Serialize("", false); err != nil || empty != "{}\n" {
		t.Fatalf("Serialize of unchanged options = %q, %v; want \"{}\\n\"", empty, err)
	}
	changes := map[string]any{
		"listen_port":     8081,
		"listen_host":     "",
		"mode":            []string{"reverse:https://example.com", "socks5@1080"},
		"ignore_hosts":    []string{`^example\.com:443$`, "true", "", "x: y"},
		"cert_passphrase": "it's a 'secret' # not a comment",
		"confdir":         "~/conf dir",
		"http2":           false,
		"key_size":        4096,
	}
	if err := m.Update(t.Context(), changes); err != nil {
		t.Fatal(err)
	}
	for _, defaults := range []bool{false, true} {
		text, err := m.Serialize("", defaults)
		if err != nil {
			t.Fatal(err)
		}
		m2 := New()
		if err := m2.Load(t.Context(), text); err != nil {
			t.Fatalf("Load(%q) = %v", text, err)
		}
		if diff := gocmp.Diff(currentValues(m), currentValues(m2)); diff != "" {
			t.Errorf("defaults=%v: Load(Serialize()) mismatch (-want +got):\n%s\nserialized:\n%s", defaults, diff, text)
		}
	}
}

// TestSaving ports test_saving of mitmproxy's test_optmanager.py.
func TestSaving(t *testing.T) {
	o := newTD2(t)
	if err := o.Update(t.Context(), map[string]any{"three": "set"}); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "conf")
	if err := o.Save(dst, true); err != nil {
		t.Fatal(err)
	}

	o2 := newTD2(t)
	if err := o2.LoadPaths(t.Context(), dst); err != nil {
		t.Fatal(err)
	}
	if err := o2.Update(t.Context(), map[string]any{"three": "foo"}); err != nil {
		t.Fatal(err)
	}
	if err := o2.Save(dst, true); err != nil {
		t.Fatal(err)
	}
	if err := o.LoadPaths(t.Context(), dst); err != nil {
		t.Fatal(err)
	}
	if got := o.Str("three"); got != "foo" {
		t.Errorf("three = %q, want foo", got)
	}

	appendFile(t, dst, "foobar: '123'")
	if err := o.LoadPaths(t.Context(), dst); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(map[string]any{"foobar": "123"}, o.Deferred()); diff != "" {
		t.Errorf("Deferred (-want +got):\n%s", diff)
	}

	appendFile(t, dst, "'''")
	requireOptionsError(t, o.LoadPaths(t.Context(), dst), "Error reading "+dst)

	for _, content := range []string{"\x01\x02\x03", "\xff\xff\xff"} {
		if err := os.WriteFile(dst, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		requireOptionsError(t, o.LoadPaths(t.Context(), dst), "Error reading "+dst)
		var oe *OptionsError
		if err := o.Save(dst, false); !errors.As(err, &oe) {
			t.Errorf("Save over %q = %v, want *OptionsError", content, err)
		}
	}
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // The path is a file the test created.
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPathsSkipsMissingAndDirectories(t *testing.T) {
	dir := t.TempDir()
	m := newTD2(t)
	if err := m.LoadPaths(t.Context(), filepath.Join(dir, "nope.yaml"), dir); err != nil {
		t.Fatalf("LoadPaths = %v, want nil", err)
	}
	if len(m.Deferred()) != 0 || m.HasChanged("one") {
		t.Error("LoadPaths changed state without loading a file")
	}
}

func TestLoadPathsLaterTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.yaml")
	b := filepath.Join(dir, "b.yaml")
	writeFile(t, a, "one: from-a\ntwo: from-a\n")
	writeFile(t, b, "two: from-b\n")
	m := newTD2(t)
	if err := m.LoadPaths(t.Context(), a, b); err != nil {
		t.Fatal(err)
	}
	if got := m.Str("one"); got != "from-a" {
		t.Errorf("one = %q, want from-a", got)
	}
	if got := m.Str("two"); got != "from-b" {
		t.Errorf("two = %q, want from-b", got)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestLoadPathsScripts ports test_load_paths: script paths in a
// configuration file are resolved relative to that file, other sequence
// options are left alone.
func TestLoadPathsScripts(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	conf := testutil.FixturePath(t, "mitmproxy/test_config.yml")
	dir := filepath.Dir(conf)

	m := NewManager()
	mustAdd(t, m, "scripts", TypeSeq, []string{}, "help")
	mustAdd(t, m, "not_scripts", TypeSeq, []string{}, "help")
	if err := m.LoadPaths(t.Context(), conf); err != nil {
		t.Fatal(err)
	}
	// pathlib keeps ".." components, so the expectations are joined by hand
	// rather than with filepath.Join, which would clean them away. "/abc" is
	// rooted but has no drive on Windows, so it lands on the drive of the
	// configuration file, as pathlib's join does.
	sep := string(filepath.Separator)
	wantScripts := []string{
		home + sep + "abc",
		dir + sep + "abc",
		dir + sep + ".." + sep + "abc",
		filepath.VolumeName(dir) + sep + "abc",
	}
	if diff := gocmp.Diff(wantScripts, m.Seq("scripts")); diff != "" {
		t.Errorf("scripts (-want +got):\n%s", diff)
	}
	if diff := gocmp.Diff([]string{"~/abc", "abc", "../abc", "/abc"}, m.Seq("not_scripts")); diff != "" {
		t.Errorf("not_scripts (-want +got):\n%s", diff)
	}
}

// TestRelativePath ports test_relative_path.
//
// The expectations are written with the platform separator. A path such as
// "/abc" is absolute on POSIX but only rooted on Windows, where pathlib puts
// it on the drive of the working directory ("D:\abc"); root is "/" on POSIX
// and that drive's root on Windows.
func TestRelativePath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	sep := string(filepath.Separator)
	root := filepath.VolumeName(wd) + sep
	join := func(elem ...string) string { return strings.Join(elem, sep) }
	tests := map[string]struct {
		script, relativeTo, want string
	}{
		"success: home, dot":           {script: "~/abc", relativeTo: ".", want: join(home, "abc")},
		"success: absolute, dot":       {script: "/abc", relativeTo: ".", want: root + "abc"},
		"success: relative, dot":       {script: "abc", relativeTo: ".", want: join(wd, "abc")},
		"success: parent, dot":         {script: "../abc", relativeTo: ".", want: join(wd, "..", "abc")},
		"success: home, absolute":      {script: "~/abc", relativeTo: "/tmp", want: join(home, "abc")},
		"success: absolute, absolute":  {script: "/abc", relativeTo: "/tmp", want: root + "abc"},
		"success: relative, absolute":  {script: "abc", relativeTo: "/tmp", want: root + join("tmp", "abc")},
		"success: parent, absolute":    {script: "../abc", relativeTo: "/tmp", want: root + join("tmp", "..", "abc")},
		"success: home, relative":      {script: "~/abc", relativeTo: "foo", want: join(home, "abc")},
		"success: absolute, relative":  {script: "/abc", relativeTo: "foo", want: root + "abc"},
		"success: relative, relative":  {script: "abc", relativeTo: "foo", want: join(wd, "foo", "abc")},
		"success: parent, relative":    {script: "../abc", relativeTo: "foo", want: join(wd, "foo", "..", "abc")},
		"success: dot components drop": {script: "./a//b/./c", relativeTo: "/tmp/", want: root + join("tmp", "a", "b", "c")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := relativePath(tt.script, tt.relativeTo); got != tt.want {
				t.Errorf("relativePath(%q, %q) = %q, want %q", tt.script, tt.relativeTo, got, tt.want)
			}
		})
	}
}

// TestPyJoinWindows checks the Windows branches of pyJoin against the
// results of Python's PureWindowsPath(a) / b, which joins with ntpath.join
// and then normalises separators.
func TestPyJoinWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("drive letters and UNC volumes exist only on Windows")
	}
	tests := map[string]struct {
		a, b, want string
	}{
		"success: relative":                        {a: `C:\dir`, b: `x`, want: `C:\dir\x`},
		"success: parent kept":                     {a: `C:\dir`, b: `x\..\y`, want: `C:\dir\x\..\y`},
		"success: absolute replaces":               {a: `C:\dir`, b: `D:\x`, want: `D:\x`},
		"success: absolute on the same drive":      {a: `C:\dir`, b: `C:\x`, want: `C:\x`},
		"success: drive-relative on another drive": {a: `C:\dir`, b: `D:x`, want: `D:x`},
		"success: drive-relative on the same drive": {
			a: `C:\dir`, b: `C:x`, want: `C:\dir\x`,
		},
		"success: drive letter case differs": {a: `C:\dir`, b: `c:x`, want: `c:\dir\x`},
		"success: rooted keeps the drive":    {a: `C:\dir`, b: `\x`, want: `C:\x`},
		"success: rooted with a slash":       {a: `C:\dir`, b: `/x`, want: `C:\x`},
		"success: UNC rooted keeps the share": {
			a: `\\host\share\dir`, b: `\x`, want: `\\host\share\x`,
		},
		"success: UNC relative":              {a: `\\host\share\dir`, b: `x`, want: `\\host\share\dir\x`},
		"success: UNC then a drive":          {a: `\\host\share\dir`, b: `C:x`, want: `C:x`},
		"success: relative then a drive":     {a: `foo`, b: `C:x`, want: `C:x`},
		"success: relative then rooted":      {a: `foo`, b: `\x`, want: `\x`},
		"success: drive-relative base":       {a: `C:foo`, b: `y`, want: `C:foo\y`},
		"success: drive-relative both sides": {a: `C:foo`, b: `C:y`, want: `C:foo\y`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := pyJoin(tt.a, tt.b); got != tt.want {
				t.Errorf("pyJoin(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// TestPyAbsoluteWindows checks pathlib's absolute() for the Windows paths
// that have a drive or a root but not both: a rooted path takes the drive of
// the working directory, and a drive-relative path on the working
// directory's drive is joined onto the working directory, as
// os.path.abspath("D:") returns it.
func TestPyAbsoluteWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("drive letters exist only on Windows")
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	drive := filepath.VolumeName(wd)
	if len(drive) != 2 || drive[1] != ':' {
		t.Skipf("working directory %q is not on a drive letter", wd)
	}
	// A working directory at a drive root ends in a separator already.
	wd = strings.TrimRight(wd, `\`)
	tests := map[string]struct {
		path, want string
	}{
		"success: rooted":               {path: `\abc`, want: drive + `\abc`},
		"success: rooted with a parent": {path: `\abc\..\x`, want: drive + `\abc\..\x`},
		"success: drive-relative":       {path: drive + `abc`, want: wd + `\abc`},
		"success: absolute stays":       {path: drive + `\abc`, want: drive + `\abc`},
		"success: relative":             {path: `abc`, want: wd + `\abc`},
		"success: relativePath with a rooted script": {
			path: relativePath(`\abc`, drive+`\tmp`), want: drive + `\abc`,
		},
		"success: relativePath with a drive-relative script": {
			path: relativePath(drive+`abc`, drive+`\tmp`), want: drive + `\tmp\abc`,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := pyAbsolute(tt.path); got != tt.want {
				t.Errorf("pyAbsolute(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := map[string]struct {
		text    string
		want    map[string]any
		wantErr string
	}{
		"success: empty":            {text: "", want: map[string]any{}},
		"success: comment only":     {text: "# a comment\n", want: map[string]any{}},
		"success: explicit null":    {text: "~\n", want: map[string]any{}},
		"success: values":           {text: "a: 1\nb: [x, 2]\nc:\nd: 'true'\n", want: map[string]any{"a": 1, "b": []any{"x", 2}, "c": nil, "d": "true"}},
		"success: anchors resolve":  {text: "a: &x [p]\nb: *x\n", want: map[string]any{"a": []any{"p"}, "b": []any{"p"}}},
		"error: scalar document":    {text: "invalid", wantErr: "Config error - no keys found."},
		"error: number document":    {text: "123", wantErr: "Config error - no keys found."},
		"error: sequence document":  {text: "- 1", wantErr: "Config error - no keys found."},
		"error: syntax error":       {text: "a: 1\n b: [\n", wantErr: "Config error at line"},
		"error: control characters": {text: "\x01\x02\x03", wantErr: "Could not parse options."},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parse(tt.text)
			if tt.wantErr != "" {
				requireOptionsError(t, err, tt.wantErr)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			flat := maps.Collect(got.All())
			if diff := gocmp.Diff(tt.want, flat); diff != "" {
				t.Errorf("parse(%q) mismatch (-want +got):\n%s", tt.text, diff)
			}
		})
	}
}

func TestParseKeepsKeyOrder(t *testing.T) {
	got, err := parse("zeta: 1\nalpha: 2\nmid: 3\n")
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]string{"zeta", "alpha", "mid"}, got.Keys()); diff != "" {
		t.Errorf("key order (-want +got):\n%s", diff)
	}
}

func TestConfigErrorSnippet(t *testing.T) {
	_, err := parse("a: 1\nb: [1, 2\n")
	var oe *OptionsError
	if !errors.As(err, &oe) {
		t.Fatalf("parse = %v, want *OptionsError", err)
	}
	if !strings.HasPrefix(oe.Msg, "Config error at line ") || !strings.Contains(oe.Msg, "^") {
		t.Errorf("message = %q, want a line number and a caret snippet", oe.Msg)
	}
}

func TestLoadTypeMismatch(t *testing.T) {
	m := New()
	var typeErr *TypeError
	if err := m.Load(t.Context(), "listen_port: abc\n"); !errors.As(err, &typeErr) {
		t.Fatalf("Load = %v, want *TypeError", err)
	}
	if m.OptInt("listen_port") != nil {
		t.Error("listen_port changed by a rejected load")
	}
}

func TestExpandUser(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	tests := map[string]struct {
		in, want string
	}{
		"success: bare tilde":        {in: "~", want: home},
		"success: tilde slash":       {in: "~/x/y", want: home + "/x/y"},
		"success: no tilde":          {in: "/a/~/b", want: "/a/~/b"},
		"success: unknown user kept": {in: "~no-such-user-for-test/x", want: "~no-such-user-for-test/x"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := expandUser(tt.in); got != tt.want {
				t.Errorf("expandUser(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
