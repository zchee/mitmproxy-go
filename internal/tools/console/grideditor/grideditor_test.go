// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package grideditor

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/strutil"
	"github.com/zchee/mitmproxy-go/internal/tools/console/external"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

func fixture(t *testing.T) *flow.HTTPFlow {
	t.Helper()
	request, err := httpmsg.MakeRequest("POST", "https://example.test/a/b?key=one&key=two", []byte("body"), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := httpmsg.MakeResponse(200, []byte("response"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f := flow.NewHTTPFlow(connection.NewClient(connection.Address{}, connection.Address{}, 1), connection.NewServer(nil), false)
	f.Request, f.Response = request, response
	return f
}

func TestConsoleGridEditor(t *testing.T) {
	t.Run("editors", func(t *testing.T) {
		tests := map[string]struct {
			part   string
			setup  func(*flow.HTTPFlow)
			verify func(*testing.T, *flow.HTTPFlow)
		}{
			"request_headers": {"request-headers", func(f *flow.HTTPFlow) {
				f.Request.Headers = httpmsg.Headers{{Name: []byte("X"), Value: []byte("first")}, {Name: []byte("X"), Value: []byte("second")}}
			}, func(t *testing.T, f *flow.HTTPFlow) {
				if diff := gocmp.Diff([]string{"first", "second"}, f.Request.Headers.GetAll("renamed")); diff != "" {
					t.Fatal(diff)
				}
			}},
			"response_headers": {"response-headers", func(f *flow.HTTPFlow) {
				f.Response.Headers = httpmsg.Headers{{Name: []byte("X"), Value: []byte("first")}}
			}, func(t *testing.T, f *flow.HTTPFlow) {
				if f.Response.Headers.Get("renamed") != "first" {
					t.Fatal(f.Response.Headers)
				}
			}},
			"query": {"query", func(*flow.HTTPFlow) {}, func(t *testing.T, f *flow.HTTPFlow) {
				if diff := gocmp.Diff([][2]string{{"renamed", "one"}, {"renamed", "two"}}, f.Request.Query()); diff != "" {
					t.Fatal(diff)
				}
			}},
			"cookies": {"cookies", func(f *flow.HTTPFlow) {
				f.Request.SetCookies([]httpmsg.CookiePair{{Name: "name", Value: "first"}, {Name: "name", Value: "second"}})
			}, func(t *testing.T, f *flow.HTTPFlow) {
				cookies := f.Request.Cookies()
				if len(cookies) != 2 || cookies[0].Name != "renamed" || cookies[1].Value != "second" {
					t.Fatal(cookies)
				}
			}},
			"set_cookies": {"set-cookies", func(f *flow.HTTPFlow) {
				f.Response.SetCookies([]httpmsg.SetCookie{{Name: "name", Value: new("first"), Attrs: httpmsg.CookieAttrs{{Name: "Secure"}, {Name: "Path", Value: new("/")}}}})
			}, func(t *testing.T, f *flow.HTTPFlow) {
				cookies := f.Response.Cookies()
				if len(cookies) != 1 || cookies[0].Name != "renamed" || !cookies[0].Attrs.Has("Secure") {
					t.Fatal(cookies)
				}
			}},
			"multipart": {"multipart form", func(f *flow.HTTPFlow) {
				if err := f.Request.SetMultipartForm([][2][]byte{{[]byte("name"), []byte("first")}, {[]byte("name"), {0xff, 0x00}}}); err != nil {
					panic(err)
				}
			}, func(t *testing.T, f *flow.HTTPFlow) {
				values := f.Request.MultipartForm()
				if len(values) != 2 || string(values[0][0]) != "renamed" || !bytes.Equal(values[1][1], []byte{0xff, 0}) {
					t.Fatal(values)
				}
			}},
			"urlencoded": {"urlencoded form", func(f *flow.HTTPFlow) {
				f.Request.SetURLEncodedForm([][2]string{{"name", "first"}, {"name", "second"}})
			}, func(t *testing.T, f *flow.HTTPFlow) {
				values := f.Request.URLEncodedForm()
				if len(values) != 2 || values[0][0] != "renamed" || values[1][1] != "second" {
					t.Fatal(values)
				}
			}},
			"path": {"path", func(*flow.HTTPFlow) {}, func(t *testing.T, f *flow.HTTPFlow) {
				if diff := gocmp.Diff([]string{"renamed", "renamed"}, f.Request.PathComponents()); diff != "" {
					t.Fatal(diff)
				}
				if len(f.Request.Query()) != 2 {
					t.Fatal("query lost")
				}
			}},
			"comment": {"comment", func(f *flow.HTTPFlow) { f.Comment = "original" }, func(t *testing.T, f *flow.HTTPFlow) {
				if f.Comment != "renamed" {
					t.Fatal(f.Comment)
				}
			}},
			"raw_bytes": {"request-body", func(f *flow.HTTPFlow) { f.Request.RawContent = []byte{0xff, 0, 1} }, func(t *testing.T, f *flow.HTTPFlow) {
				if string(f.Request.RawContent) != "renamed" {
					t.Fatal(f.Request.RawContent)
				}
			}},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				f := fixture(t)
				tt.setup(f)
				session, err := external.Capture(f, tt.part, contract.DetailOptions{})
				if err != nil {
					t.Fatal(err)
				}
				m, err := New(t.Context(), nil, session)
				if err != nil {
					t.Fatal(err)
				}
				rows := m.Values()
				if len(rows) == 0 {
					t.Fatal("no working rows")
				}
				for i := range rows {
					rows[i][0].Data = []byte("renamed")
				}
				edit, err := PrepareRows(session, rows)
				if err != nil {
					t.Fatal(err)
				}
				hash, err := external.Fingerprint(f, edit.Target)
				if err != nil || hash != edit.Target.Fingerprint {
					t.Fatal("snapshot changed before apply", err)
				}
				f.Backup()
				edit.Apply(f, edit.Target)
				tt.verify(t, f)
				if !f.Modified() {
					t.Fatal("missing modification")
				}
				if err := f.Revert(); err != nil {
					t.Fatal(err)
				}
				if cmd, consumed := m.Update(contract.Action{Kind: "grid", Value: "add"}); cmd != nil || !consumed {
					t.Fatal("admitted grid add was not consumed")
				}
				if !m.editing {
					t.Fatal("add did not enter cell")
				}
				m.input = `bad\x`
				if m.finish() {
					t.Fatal("invalid escape accepted")
				}
				if result, ok := m.Commit()().(contract.ErrorMsg); !ok || result.Err == nil {
					t.Fatal("invalid pending edit did not preserve the editor with an error")
				}
				m.input = `value\n`
				if !m.finish() {
					t.Fatal(m.err)
				}
				m.Delete()
				m.Update(tea.KeyPressMsg{Code: tea.KeyTab})
				m.Resize(40, 4)
				if strings.Contains(m.View(), "\x1b]52") {
					t.Fatal("control output")
				}
			})
		}
	})
	t.Run("files", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"read": {func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "bytes")
				want := []byte{0, 0xff, '\n'}
				if err := os.WriteFile(path, want, 0o600); err != nil {
					t.Fatal(err)
				}
				got, err := ReadFile(path, false)
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(want, got); diff != "" {
					t.Fatal(diff)
				}
			}},
			"escaped": {func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "escaped")
				if err := os.WriteFile(path, []byte(`\x00\xff\n`), 0o600); err != nil {
					t.Fatal(err)
				}
				got, err := ReadFile(path, true)
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff([]byte{0, 0xff, '\n'}, got); diff != "" {
					t.Fatal(diff)
				}
			}},
			"save": {func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "rows.csv")
				rows := [][]Cell{{{Data: []byte("key")}, {Data: []byte("line\r\nsecond,\"quoted\"")}}}
				if err := SaveFile(path, rows); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				want := "key,\"line\r\nsecond,\"\"quoted\"\"\"\r\n"
				if string(data) != want {
					t.Fatalf("got=%q want=%q", data, want)
				}
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != 0o600 {
					t.Fatal("not private", err)
				}
				tests := map[string]struct {
					rows [][]Cell
					want string
				}{
					"empty row":         {[][]Cell{nil}, "\r\n"},
					"empty field":       {[][]Cell{{{}}}, "\"\"\r\n"},
					"empty pair":        {[][]Cell{{{}, {}}}, ",\r\n"},
					"whitespace":        {[][]Cell{{{Data: []byte(" leading ")}, {Data: []byte("\tvalue")}}}, " leading ,\tvalue\r\n"},
					"dot escape":        {[][]Cell{{{Data: []byte(`\.`)}}}, "\\.\r\n"},
					"embedded controls": {[][]Cell{{{Data: []byte("a\rb\nc")}}}, "\"a\rb\nc\"\r\n"},
				}
				for name, tt := range tests {
					var output bytes.Buffer
					if err := writeCSV(&output, tt.rows); err != nil {
						t.Fatal(name, err)
					}
					if diff := gocmp.Diff(tt.want, output.String()); diff != "" {
						t.Fatal(name, diff)
					}
				}
			}},
			"invalid": {func(t *testing.T) {
				if _, err := ReadFile(filepath.Join(t.TempDir(), "missing"), false); err == nil {
					t.Fatal("missing path accepted")
				}
				if _, err := DecodeEscaped(`\x`); err == nil {
					t.Fatal("malformed escape accepted")
				}
				if err := SaveFile(t.TempDir(), nil); err == nil {
					t.Fatal("directory accepted")
				}
			}},
			"owner_path": {func(t *testing.T) {
				dir := t.TempDir()
				target := filepath.Join(dir, "target")
				if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(dir, "link")
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				if err := SaveFile(link, [][]Cell{{{Data: []byte("bad")}}}); err == nil {
					t.Fatal("symlink accepted")
				}
				got, err := os.ReadFile(target)
				if err != nil || string(got) != "keep" {
					t.Fatal("target changed", err)
				}
			}},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}

func FuzzConsoleGridEscaped(f *testing.F) {
	for _, seed := range []string{"hello", `\x00\xff`, "\\", "日", `\777`, "", "header value", `\x00\x7f\xff`, `line\nnext\tcolumn\\`, `€\U0001f642`, `\x0g`, "abc\\", "\xff\xfe"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		data, err := DecodeEscaped(input)
		if err != nil {
			return
		}
		encoded := strutil.BytesToEscapedStr(data, false, false)
		roundtrip, err := DecodeEscaped(encoded)
		if err != nil || !bytes.Equal(data, roundtrip) {
			t.Fatalf("roundtrip failed: %q", encoded)
		}
	})
}
