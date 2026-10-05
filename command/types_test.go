// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package command_test

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
)

// TestTypesUpstream ports test_types.py's scalar, collection, and choice tests.
// test_path is in TestPathTypeUpstream; test_flow and test_flows are in
// TestFlowTypesUpstream. Their DummyConsole resolver is a registered command,
// not the view addon's filter language. Actual view selection remains the
// responsibility of the view addon.
func TestTypesUpstream(t *testing.T) {
	type parseCase struct {
		text string
		want any
		bad  bool
	}
	type validCase struct {
		value any
		want  bool
	}
	tests := map[string]struct {
		typ           command.Type
		parse         []parseCase
		valid         []validCase
		completion    []string
		completionErr bool
	}{
		"test_bool":                   {typ: command.BoolType, parse: []parseCase{{"true", true, false}, {"false", false, false}, {"foo", nil, true}}, valid: []validCase{{true, true}, {"foo", false}}, completion: []string{"false", "true"}},
		"test_str":                    {typ: command.StrType, parse: []parseCase{{"foo", "foo", false}, {`foo\nbar`, "foo\nbar", false}, {`\N{BELL}`, "🔔", false}, {`\N{UNKNOWN UNICODE SYMBOL!}`, nil, true}}, valid: []validCase{{"foo", true}, {1, false}}},
		"test_bytes":                  {typ: command.BytesType, parse: []parseCase{{"foo", []byte("foo"), false}, {"incomplete escape sequence\\", nil, true}}, valid: []validCase{{[]byte("foo"), true}, {1, false}}},
		"test_unknown":                {typ: command.UnknownType, parse: []parseCase{{"foo", "foo", false}}, valid: []validCase{{"foo", false}, {1, false}}},
		"test_int":                    {typ: command.IntType, parse: []parseCase{{"1", 1, false}, {"999", 999, false}, {"foo", nil, true}}, valid: []validCase{{"foo", false}, {1, true}}},
		"test_cmd":                    {typ: command.CmdType, parse: []parseCase{{"cmd1", command.Cmd("cmd1"), false}, {"foo", nil, true}}, valid: []validCase{{"foo", false}, {"cmd1", true}}, completion: []string{"cmd1", "options"}},
		"test_marker":                 {typ: command.MarkerType, parse: []parseCase{{":red_circle:", command.Marker(":red_circle:"), false}, {"true", command.Marker(":default:"), false}, {"false", command.Marker(""), false}, {":bogus:", nil, true}}, valid: []validCase{{"true", true}, {"false", true}, {"bogus", false}, {"X", true}, {":red_circle:", true}}},
		"test_arg":                    {typ: command.ArgType, parse: []parseCase{{"foo", command.CmdArgs("foo"), false}}, valid: []validCase{{1, false}}},
		"test_strseq":                 {typ: command.StrSeqType, parse: []parseCase{{"foo", []string{"foo"}, false}, {"foo,bar", []string{"foo", "bar"}, false}}, valid: []validCase{{[]string{"foo"}, true}, {[]any{"a", "b", 3}, false}, {1, false}, {"foo", false}}},
		"test_data":                   {typ: command.DataType, parse: []parseCase{{"foo", nil, true}}, valid: []validCase{{0, false}, {command.Data{}, true}, {command.Data{{"x"}}, true}, {command.Data{{[]byte("x")}}, true}, {command.Data{{1}}, false}}, completionErr: true},
		"test_choice":                 {typ: command.Choice("options"), parse: []parseCase{{"one", "one", false}, {"invalid", nil, true}}, valid: []validCase{{"one", true}, {"invalid", false}}, completion: []string{"one", "two", "three"}},
		"test_choice missing command": {typ: command.Choice("nonexistent"), parse: []parseCase{{"invalid", nil, true}}, valid: []validCase{{"invalid", false}}, completionErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := command.NewManager()
			if err := m.Register("cmd1", func(context.Context) {}); err != nil {
				t.Fatal(err)
			}
			if err := m.Register("options", func(context.Context) []string { return []string{"one", "two", "three"} }); err != nil {
				t.Fatal(err)
			}
			for _, p := range tt.parse {
				got, err := tt.typ.Parse(t.Context(), m, p.text)
				if (err != nil) != p.bad {
					t.Errorf("Parse(%q) = %v, %v; want error %t", p.text, got, err, p.bad)
					continue
				}
				if !p.bad {
					if diff := cmp.Diff(p.want, got); diff != "" {
						t.Errorf("Parse(%q) (-want +got):\n%s", p.text, diff)
					}
				}
			}
			for _, v := range tt.valid {
				if got := tt.typ.IsValid(t.Context(), m, v.value); got != v.want {
					t.Errorf("IsValid(%#v) = %t, want %t", v.value, got, v.want)
				}
			}
			got, err := tt.typ.Completion(t.Context(), m, "")
			if (err != nil) != tt.completionErr {
				t.Fatalf("Completion error = %v, want error %t", err, tt.completionErr)
			}
			if tt.typ == command.MarkerType {
				if len(got) <= 10 || !slices.Contains(got, ":red_circle:") {
					t.Errorf("marker completion lacks upstream markers: %v", got)
				}
			} else if diff := cmp.Diff(tt.completion, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Completion (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCutSpecTypeUpstream(t *testing.T) {
	m := command.NewManager()
	b := command.CutSpecType
	got, err := b.Parse(t.Context(), m, "foo,bar")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(command.CutSpec{"foo", "bar"}, got); diff != "" {
		t.Fatal(diff)
	}
	tests := map[string]struct {
		value any
		want  bool
	}{
		"integer": {1, false}, "unknown": {"foo", false}, "known": {"request.path", true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := b.IsValid(t.Context(), m, tt.value); got != tt.want {
				t.Errorf("IsValid(%v) = %t", tt.value, got)
			}
		})
	}
	want := []string{"request.method", "request.scheme", "request.host", "request.http_version", "request.port", "request.path", "request.url", "request.text", "request.content", "request.raw_content", "request.timestamp_start", "request.timestamp_end", "request.header[", "response.status_code", "response.reason", "response.text", "response.content", "response.timestamp_start", "response.timestamp_end", "response.raw_content", "response.header[", "client_conn.peername.port", "client_conn.peername.host", "client_conn.tls_version", "client_conn.sni", "client_conn.tls_established", "server_conn.address.port", "server_conn.address.host", "server_conn.ip_address.host", "server_conn.tls_version", "server_conn.sni", "server_conn.tls_established"}
	completion, err := b.Completion(t.Context(), m, "request.p")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, completion); diff != "" {
		t.Fatal(diff)
	}
	for i := range want {
		want[i] = "request.port," + want[i]
	}
	completion, err = b.Completion(t.Context(), m, "request.port,f")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, completion); diff != "" {
		t.Fatal(diff)
	}
}

func TestPathTypeUpstream(t *testing.T) {
	m := command.NewManager()
	t.Setenv("HOME", "/home/test")
	t.Setenv("USERPROFILE", "/home/test")
	tests := map[string]struct {
		text string
		want command.Path
	}{
		"foo": {"/foo", "/foo"}, "bar": {"/bar", "/bar"}, "home": {"~/mitm", "/home/test/mitm"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := command.PathType.Parse(t.Context(), m, tt.text)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	for _, value := range []any{"foo", "~/mitm", 3} {
		_, want := value.(string)
		if got := command.PathType.IsValid(t.Context(), m, value); got != want {
			t.Errorf("IsValid(%v) = %t", value, got)
		}
	}
	dir := t.TempDir()
	for _, name := range []string{"aaa", "aab", "aac"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "bbb"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	completions := map[string]struct {
		input, trim string
		want        []string
	}{
		"directory":   {dir, dir, []string{"/aaa", "/aab", "/aac", "/bbb/"}},
		"prefix":      {filepath.Join(dir, "a"), dir, []string{"/aaa", "/aab", "/aac"}},
		"relative":    {"./", "", []string{"./aaa", "./aab", "./aac", "./bbb/"}},
		"empty":       {"", "", []string{"./aaa", "./aab", "./aac", "./bbb/"}},
		"nonexistent": {"nonexistent", "", []string{"nonexistent"}},
	}
	for name, tt := range completions {
		t.Run(name, func(t *testing.T) {
			got, err := command.PathType.Completion(t.Context(), m, tt.input)
			if err != nil {
				t.Fatal(err)
			}
			for i := range got {
				got[i] = filepath.ToSlash(strings.TrimPrefix(got[i], tt.trim))
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Completion(%q) (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}

func TestFlowTypesUpstream(t *testing.T) {
	m := command.NewManager()
	f := flow.NewHTTPFlow(nil, nil, false)
	if err := m.Register("view.flows.resolve", func(_ context.Context, spec string) ([]flow.Flow, error) {
		if spec == "err" {
			return nil, errBoom
		}
		n, err := strconv.Atoi(spec)
		if err != nil {
			n = 1
		}
		return slices.Repeat([]flow.Flow{f}, n), nil
	}); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		typ  command.Type
		text string
		want int
		bad  bool
	}{
		"test_flow one":    {command.FlowType, "1", 1, false},
		"test_flow space":  {command.FlowType, "has space", 1, false},
		"test_flow zero":   {command.FlowType, "0", 0, true},
		"test_flow two":    {command.FlowType, "2", 0, true},
		"test_flow error":  {command.FlowType, "err", 0, true},
		"test_flows zero":  {command.FlowsType, "0", 0, false},
		"test_flows one":   {command.FlowsType, "1", 1, false},
		"test_flows two":   {command.FlowsType, "2", 2, false},
		"test_flows space": {command.FlowsType, "has space", 1, false},
		"test_flows error": {command.FlowsType, "err", 0, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := tt.typ.Parse(t.Context(), m, tt.text)
			if (err != nil) != tt.bad {
				t.Fatalf("Parse(%q) = %v, %v; want error %t", tt.text, got, err, tt.bad)
			}
			if tt.bad {
				return
			}
			if tt.typ == command.FlowType {
				if got != f {
					t.Fatal("single flow identity was not preserved")
				}
			} else {
				fs := got.([]flow.Flow)
				if len(fs) != tt.want {
					t.Fatalf("got %d flows, want %d", len(fs), tt.want)
				}
				for _, item := range fs {
					if item != f {
						t.Fatal("flow identity was not preserved")
					}
				}
			}
		})
	}
	valid := map[string]struct {
		typ   command.Type
		value any
		want  bool
	}{
		"flow": {command.FlowType, f, true}, "flow text": {command.FlowType, "xx", false},
		"flows": {command.FlowsType, []flow.Flow{f}, true}, "flows text": {command.FlowsType, "xx", false}, "flows integer": {command.FlowsType, 0, false},
		"nil flow": {command.FlowType, (*flow.HTTPFlow)(nil), false}, "nil element": {command.FlowsType, []flow.Flow{nil}, false}, "typed nil element": {command.FlowsType, []flow.Flow{(*flow.HTTPFlow)(nil)}, false},
	}
	for name, tt := range valid {
		t.Run(name, func(t *testing.T) {
			if got := tt.typ.IsValid(t.Context(), m, tt.value); got != tt.want {
				t.Errorf("IsValid(%v) = %t, want %t", tt.value, got, tt.want)
			}
		})
	}
	want := []string{"@all", "@focus", "@shown", "@hidden", "@marked", "@unmarked", "~q", "~s", "~a", "~hq", "~hs", "~b", "~bq", "~bs", "~t", "~d", "~m", "~u", "~c"}
	for _, typ := range []command.Type{command.FlowType, command.FlowsType} {
		got, err := typ.Completion(t.Context(), m, "")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Error(diff)
		}
	}
}

// test_typemanager is expressed through TypeFor and Choice: Python's type
// object lookups are registration-time operations in Go.
func TestTypeManagerUpstream(t *testing.T) {
	got, err := command.TypeFor(reflect.TypeFor[bool]())
	if err != nil || got != command.BoolType {
		t.Fatalf("TypeFor(bool) = %v, %v", got, err)
	}
	m := command.NewManager()
	if err := m.Register("choose", func(context.Context, string) {}, command.WithParams("value"), command.WithArgument("value", command.Choice("choide"))); err != nil {
		t.Fatal(err)
	}
}

func TestArgumentEdgeCases(t *testing.T) {
	tests := map[string]struct {
		typ  command.Type
		text string
		want any
		bad  bool
	}{
		"integer digit limit":                        {command.IntType, strings.Repeat("0", 4300), 0, false},
		"integer above digit limit":                  {command.IntType, strings.Repeat("0", 4301), nil, true},
		"unicode decimal":                            {command.IntType, " +١_२３ ", 123, false},
		"nondecimal numeral":                         {command.IntType, "²", nil, true},
		"unicode whitespace":                         {command.IntType, " 1 ", 1, false},
		"record separator is not integer whitespace": {command.IntType, "\x1c1", nil, true},
		"double sign":                                {command.IntType, "--1", nil, true},
		"double underscore":                          {command.IntType, "1__0", nil, true},
		"leading underscore":                         {command.IntType, "_1", nil, true},
		"trailing underscore":                        {command.IntType, "1_", nil, true},
		"named alias":                                {command.StrType, `\N{LF}`, "\n", false},
		"named sequence rejected by codec":           {command.StrType, `\N{KEYCAP DIGIT ONE}`, nil, true},
		"case insensitive name":                      {command.StrType, `\N{latin small letter a}`, "a", false},
		"negative codepoint spelling":                {command.StrType, `\x-1`, nil, true},
		"short escape unchanged":                     {command.StrType, `\x1`, `\x1`, false},
		"unknown escape unchanged":                   {command.StrType, `\q`, `\q`, false},
		"octal":                                      {command.StrType, `\777`, "ǿ", false},
		"strip separators in sequence":               {command.StrSeqType, "\x1ca\x1f, b ", []string{"a", "b"}, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := tt.typ.Parse(t.Context(), command.NewManager(), tt.text)
			if (err != nil) != tt.bad {
				t.Fatalf("Parse(%q) = %v, %v; want error %t", tt.text, got, err, tt.bad)
			}
			if !tt.bad {
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Error(diff)
				}
			}
		})
	}
}

func TestMarkerCompletionOwnership(t *testing.T) {
	m := command.NewManager()
	first, err := command.MarkerType.Completion(t.Context(), m, "")
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(first)
	first[0] = "changed by caller"
	t.Cleanup(func() { first[0] = want[0] })
	second, err := command.MarkerType.Completion(t.Context(), m, "")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, second); diff != "" {
		t.Errorf("caller mutated shared completions:\n%s", diff)
	}
}

func TestPathNamedUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", `C:\Users\current`)
		t.Setenv("USERNAME", "current")
		tests := map[string]struct{ input, want string }{
			"current": {`~current\mitm`, `C:\Users\current\mitm`},
			"guest":   {`~guest/mitm`, `C:\Users\guest/mitm`},
			"home":    {`~\mitm`, `C:\Users\current\mitm`},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				got, err := command.PathType.Parse(t.Context(), command.NewManager(), tt.input)
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(command.Path(tt.want), got); diff != "" {
					t.Error(diff)
				}
			})
		}
		return
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	got, err := command.PathType.Parse(t.Context(), command.NewManager(), "~"+u.Username+"/mitm")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(command.Path(strings.TrimRight(u.HomeDir, "/")+"/mitm"), got); diff != "" {
		t.Error(diff)
	}
}

func TestFlowMissingResolver(t *testing.T) {
	m := command.NewManager()
	if err := m.Register("flow.kill", func(context.Context, []flow.Flow) {}); err != nil {
		t.Fatal(err)
	}
	_, err := m.Execute(t.Context(), "flow.kill @all")
	if !errors.Is(err, command.ErrInvalidArgument) || !errors.Is(err, command.ErrUnknownCommand) || !strings.Contains(err.Error(), "@all") || !strings.Contains(err.Error(), "view.flows.resolve") {
		t.Fatalf("missing resolver error lacks argument or sentinels: %v", err)
	}
}
