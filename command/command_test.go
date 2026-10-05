// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package command_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// unsupported is a Go type with no command type identity.
type unsupported struct{}

// typeID renders an identity for comparison, including the options command
// of a choice so that two different choices do not compare equal.
func typeID(t command.Type) string {
	switch t := t.(type) {
	case nil:
		return ""
	case command.ChoiceType:
		return fmt.Sprintf("Choice(%s)", t.OptionsCommand)
	default:
		return t.Name()
	}
}

// summary is the comparable view of a registered command.
type summary struct {
	Help      string
	Params    []string
	Return    string
	Signature string
}

func summarize(c *command.Command) summary {
	s := summary{Help: c.Help, Return: typeID(c.Return), Signature: c.SignatureHelp()}
	for _, p := range c.Params {
		s.Params = append(s.Params, p.String()+":"+typeID(p.Type))
	}
	return s
}

func lookup(t *testing.T, m *command.Manager, name string) *command.Command {
	t.Helper()
	for n, c := range m.Commands() {
		if n == name {
			return c
		}
	}
	t.Fatalf("command %q is not registered", name)
	return nil
}

func TestTypeIdentities(t *testing.T) {
	tests := map[string]struct {
		typ         command.Type
		wantName    string
		wantDisplay string
	}{
		"success: arg":     {typ: command.ArgType, wantName: "Arg", wantDisplay: "arg"},
		"success: bool":    {typ: command.BoolType, wantName: "Bool", wantDisplay: "bool"},
		"success: choice":  {typ: command.Choice("foo"), wantName: "Choice", wantDisplay: "choice"},
		"success: cmd":     {typ: command.CmdType, wantName: "Cmd", wantDisplay: "cmd"},
		"success: cutspec": {typ: command.CutSpecType, wantName: "CutSpec", wantDisplay: "cut[]"},
		"success: data":    {typ: command.DataType, wantName: "Data", wantDisplay: "data[][]"},
		"success: flow":    {typ: command.FlowType, wantName: "Flow", wantDisplay: "flow"},
		"success: flows":   {typ: command.FlowsType, wantName: "Flows", wantDisplay: "flow[]"},
		"success: int":     {typ: command.IntType, wantName: "Int", wantDisplay: "int"},
		"success: marker":  {typ: command.MarkerType, wantName: "Marker", wantDisplay: "marker"},
		"success: path":    {typ: command.PathType, wantName: "Path", wantDisplay: "path"},
		"success: str":     {typ: command.StrType, wantName: "Str", wantDisplay: "str"},
		"success: strseq":  {typ: command.StrSeqType, wantName: "StrSeq", wantDisplay: "str[]"},
		"success: bytes":   {typ: command.BytesType, wantName: "Bytes", wantDisplay: "bytes"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := [2]string{tt.typ.Name(), tt.typ.Display()}
			want := [2]string{tt.wantName, tt.wantDisplay}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("identity (-want +got):\n%s", diff)
			}
		})
	}
}

func TestChoiceIdentity(t *testing.T) {
	if command.Choice("a") != command.Choice("a") {
		t.Error("two choices over the same options command must be equal")
	}
	if command.Choice("a") == command.Choice("b") {
		t.Error("choices over different options commands must differ")
	}
}

func TestTypeFor(t *testing.T) {
	tests := map[string]struct {
		goType  reflect.Type
		want    command.Type
		wantErr string
	}{
		"success: string":        {goType: reflect.TypeFor[string](), want: command.StrType},
		"success: bool":          {goType: reflect.TypeFor[bool](), want: command.BoolType},
		"success: int":           {goType: reflect.TypeFor[int](), want: command.IntType},
		"success: bytes":         {goType: reflect.TypeFor[[]byte](), want: command.BytesType},
		"success: string slice":  {goType: reflect.TypeFor[[]string](), want: command.StrSeqType},
		"success: path":          {goType: reflect.TypeFor[command.Path](), want: command.PathType},
		"success: cmd":           {goType: reflect.TypeFor[command.Cmd](), want: command.CmdType},
		"success: cmd args":      {goType: reflect.TypeFor[command.CmdArgs](), want: command.ArgType},
		"success: marker":        {goType: reflect.TypeFor[command.Marker](), want: command.MarkerType},
		"success: cut spec":      {goType: reflect.TypeFor[command.CutSpec](), want: command.CutSpecType},
		"success: data":          {goType: reflect.TypeFor[command.Data](), want: command.DataType},
		"success: flow":          {goType: reflect.TypeFor[flow.Flow](), want: command.FlowType},
		"success: flow slice":    {goType: reflect.TypeFor[[]flow.Flow](), want: command.FlowsType},
		"error: concrete flow":   {goType: reflect.TypeFor[*flow.HTTPFlow](), wantErr: "unsupported type"},
		"error: concrete flows":  {goType: reflect.TypeFor[[]*flow.TCPFlow](), wantErr: "unsupported type"},
		"error: struct":          {goType: reflect.TypeFor[unsupported](), wantErr: "unsupported type"},
		"error: int64":           {goType: reflect.TypeFor[int64](), wantErr: "unsupported type"},
		"error: empty interface": {goType: reflect.TypeFor[any](), wantErr: "unsupported type"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := command.TypeFor(tt.goType)
			if tt.wantErr != "" {
				if !errors.Is(err, command.ErrSignature) || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("TypeFor(%v) error = %v, want ErrSignature containing %q", tt.goType, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("TypeFor(%v): %v", tt.goType, err)
			}
			if got != tt.want {
				t.Errorf("TypeFor(%v) = %s, want %s", tt.goType, typeID(got), typeID(tt.want))
			}
		})
	}
}

func TestRegisterSignature(t *testing.T) {
	tests := map[string]struct {
		name        string
		fn          any
		opts        []command.Option
		want        summary
		wantErr     error
		wantErrText string
	}{
		"success: no return value": {
			name: "noret",
			fn:   func(context.Context) {},
			want: summary{Signature: "noret "},
		},
		"success: string to string with help": {
			name: "cmd.path",
			fn:   func(_ context.Context, foo string) string { return "ret " + foo },
			opts: []command.Option{command.WithParams("foo"), command.WithHelp("  cmd1 help\n")},
			want: summary{Help: "cmd1 help", Params: []string{"foo:Str"}, Return: "Str", Signature: "cmd.path foo -> str"},
		},
		"success: mixed parameter types": {
			name: "cmd4",
			fn:   func(_ context.Context, a int, b string, c command.Path) string { return "ok" },
			opts: []command.Option{command.WithParams("a", "b", "c")},
			want: summary{Params: []string{"a:Int", "b:Str", "c:Path"}, Return: "Str", Signature: "cmd4 a b c -> str"},
		},
		"success: subcommand with variadic arguments": {
			name: "subcommand",
			fn:   func(_ context.Context, cmd command.Cmd, args ...command.CmdArgs) string { return "ok" },
			opts: []command.Option{command.WithParams("cmd", "args")},
			want: summary{Params: []string{"cmd:Cmd", "*args:Arg"}, Return: "Str", Signature: "subcommand cmd *args -> str"},
		},
		"success: variadic strings return a sequence": {
			name: "varargs",
			fn:   func(_ context.Context, one string, v ...string) []string { return v },
			opts: []command.Option{command.WithParams("one", "var")},
			want: summary{Params: []string{"one:Str", "*var:Str"}, Return: "StrSeq", Signature: "varargs one *var -> str[]"},
		},
		"success: choice argument": {
			name: "choose",
			fn:   func(_ context.Context, arg string) []string { return nil },
			opts: []command.Option{command.WithParams("arg"), command.WithArgument("arg", command.Choice("choices"))},
			want: summary{Params: []string{"arg:Choice(choices)"}, Return: "StrSeq", Signature: "choose arg -> str[]"},
		},
		"success: explicit identity matching the Go type": {
			name: "path",
			fn:   func(_ context.Context, arg command.Path) {},
			opts: []command.Option{command.WithParams("arg"), command.WithArgument("arg", command.PathType)},
			want: summary{Params: []string{"arg:Path"}, Signature: "path arg"},
		},
		"success: default parameter names": {
			name: "defaults",
			fn:   func(context.Context, int, bool, ...[]byte) command.Data { return nil },
			want: summary{Params: []string{"arg0:Int", "arg1:Bool", "*arg2:Bytes"}, Return: "Data", Signature: "defaults arg0 arg1 *arg2 -> data[][]"},
		},
		"success: leading context is not a parameter": {
			name: "ctx",
			fn:   func(ctx context.Context, m command.Marker) (command.CutSpec, error) { return nil, nil },
			opts: []command.Option{command.WithParams("marker")},
			want: summary{Params: []string{"marker:Marker"}, Return: "CutSpec", Signature: "ctx marker -> cut[]"},
		},
		"success: flow list argument": {
			name: "flow.kill",
			fn:   func(_ context.Context, flows []flow.Flow) {},
			opts: []command.Option{command.WithParams("flows")},
			want: summary{Params: []string{"flows:Flows"}, Signature: "flow.kill flows"},
		},
		"success: single flow argument and flow list result": {
			name: "flow.one",
			fn:   func(_ context.Context, f flow.Flow, spec string) ([]flow.Flow, error) { return nil, nil },
			opts: []command.Option{command.WithParams("f", "spec")},
			want: summary{Params: []string{"f:Flow", "spec:Str"}, Return: "Flows", Signature: "flow.one f spec -> flow[]"},
		},
		"success: variadic flows map on the element": {
			name: "flow.each",
			fn:   func(_ context.Context, fs ...flow.Flow) flow.Flow { return nil },
			opts: []command.Option{command.WithParams("fs")},
			want: summary{Params: []string{"*fs:Flow"}, Return: "Flow", Signature: "flow.each *fs -> flow"},
		},
		"success: explicit flow identities": {
			name: "flow.explicit",
			fn:   func(_ context.Context, f flow.Flow, fs []flow.Flow) {},
			opts: []command.Option{command.WithParams("f", "fs"), command.WithArgument("f", command.FlowType), command.WithArgument("fs", command.FlowsType)},
			want: summary{Params: []string{"f:Flow", "fs:Flows"}, Signature: "flow.explicit f fs"},
		},
		"error: concrete flow list argument": {
			name:    "flow.http",
			fn:      func(_ context.Context, flows []*flow.HTTPFlow) {},
			wantErr: command.ErrSignature,
		},
		"success: error-only result has no return type": {
			name: "errorish",
			fn:   func(_ context.Context, s []string) error { return nil },
			want: summary{Params: []string{"arg0:StrSeq"}, Signature: "errorish arg0"},
		},
		"error: unsupported return type": {
			name:    "invalidret",
			fn:      func(context.Context) unsupported { return unsupported{} },
			wantErr: command.ErrSignature,
		},
		"error: unsupported argument type": {
			name:    "invalidarg",
			fn:      func(_ context.Context, u unsupported) {},
			wantErr: command.ErrSignature,
		},
		"error: unsupported variadic element type": {
			name:    "invalidvariadic",
			fn:      func(_ context.Context, u ...unsupported) {},
			wantErr: command.ErrSignature,
		},
		"error: context not in first position": {
			name:        "latectx",
			fn:          func(s string, ctx context.Context) {},
			wantErr:     command.ErrSignature,
			wantErrText: "command latectx: the first parameter must be a context.Context",
		},
		"error: no parameters and no context": {
			name:        "noctx",
			fn:          func() {},
			wantErr:     command.ErrSignature,
			wantErrText: "command noctx: the first parameter must be a context.Context, which carries the dispatch frame, got func()",
		},
		"error: parameters without a context": {
			name:        "noctx.args",
			fn:          func(foo string) string { return foo },
			wantErr:     command.ErrSignature,
			wantErrText: "command noctx.args: the first parameter must be a context.Context, which carries the dispatch frame, got func(string) string",
		},
		"error: second result is not an error": {
			name:    "tworesults",
			fn:      func(context.Context) (string, string) { return "", "" },
			wantErr: command.ErrSignature,
		},
		"error: three results": {
			name:    "threeresults",
			fn:      func(context.Context) (string, int, error) { return "", 0, nil },
			wantErr: command.ErrSignature,
		},
		"error: not a function": {
			name:    "notfunc",
			fn:      "cmd",
			wantErr: command.ErrSignature,
		},
		"error: nil function": {
			name:    "nilfunc",
			fn:      (func(context.Context))(nil),
			wantErr: command.ErrSignature,
		},
		"error: empty command name": {
			name:    "",
			fn:      func(context.Context) {},
			wantErr: command.ErrSignature,
		},
		"error: too few parameter names": {
			name:    "names",
			fn:      func(_ context.Context, a, b string) {},
			opts:    []command.Option{command.WithParams("a")},
			wantErr: command.ErrSignature,
		},
		"error: repeated parameter name": {
			name:    "names",
			fn:      func(_ context.Context, a, b string) {},
			opts:    []command.Option{command.WithParams("a", "a")},
			wantErr: command.ErrSignature,
		},
		"error: empty parameter name": {
			name:    "names",
			fn:      func(_ context.Context, a string) {},
			opts:    []command.Option{command.WithParams("")},
			wantErr: command.ErrSignature,
		},
		"error: argument override for unknown parameter": {
			name:    "choose",
			fn:      func(_ context.Context, arg string) {},
			opts:    []command.Option{command.WithParams("arg"), command.WithArgument("nope", command.Choice("choices"))},
			wantErr: command.ErrSignature,
		},
		"error: choice on a non-string parameter": {
			name:    "choose",
			fn:      func(_ context.Context, arg int) {},
			opts:    []command.Option{command.WithParams("arg"), command.WithArgument("arg", command.Choice("choices"))},
			wantErr: command.ErrSignature,
		},
		"error: identity bound to a different Go type": {
			name:    "path",
			fn:      func(_ context.Context, arg string) {},
			opts:    []command.Option{command.WithParams("arg"), command.WithArgument("arg", command.PathType)},
			wantErr: command.ErrSignature,
		},
		"error: flow identity on a string parameter": {
			name:    "flow",
			fn:      func(_ context.Context, arg string) {},
			opts:    []command.Option{command.WithParams("arg"), command.WithArgument("arg", command.FlowType)},
			wantErr: command.ErrSignature,
		},
		"error: flows identity on a single flow parameter": {
			name:    "flows",
			fn:      func(_ context.Context, arg flow.Flow) {},
			opts:    []command.Option{command.WithParams("arg"), command.WithArgument("arg", command.FlowsType)},
			wantErr: command.ErrSignature,
		},
		"error: nil argument identity": {
			name:    "nilarg",
			fn:      func(_ context.Context, arg string) {},
			opts:    []command.Option{command.WithParams("arg"), command.WithArgument("arg", nil)},
			wantErr: command.ErrSignature,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := command.NewManager()
			err := m.Register(tt.name, tt.fn, tt.opts...)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) || !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("Register(%q) error = %v, want %v containing %q", tt.name, err, tt.wantErr, tt.wantErrText)
				}
				for n := range m.Commands() {
					t.Errorf("failed registration left command %q behind", n)
				}
				return
			}
			if err != nil {
				t.Fatalf("Register(%q): %v", tt.name, err)
			}
			if diff := cmp.Diff(tt.want, summarize(lookup(t, m, tt.name))); diff != "" {
				t.Errorf("command (-want +got):\n%s", diff)
			}
		})
	}
}

type ctxKey struct{}

var errBoom = errors.New("boom")

func newTestManager(t *testing.T) *command.Manager {
	t.Helper()
	m := command.NewManager()
	regs := []struct {
		name string
		fn   any
		opts []command.Option
	}{
		{"one.two", func(_ context.Context, foo string) string { return "ret " + foo }, []command.Option{command.WithParams("foo"), command.WithHelp("cmd1 help")}},
		{"cmd3", func(_ context.Context, foo int) int { return foo }, []command.Option{command.WithParams("foo")}},
		{"empty", func(context.Context) {}, nil},
		{"varargs", func(_ context.Context, one string, v ...string) []string { return v }, []command.Option{command.WithParams("one", "var")}},
		{"cut", func(_ context.Context, spec command.CutSpec) int { return len(spec) }, []command.Option{command.WithParams("spec")}},
		{"fail", func(context.Context) (string, error) { return "partial", errBoom }, nil},
		{"failonly", func(context.Context) error { return errBoom }, nil},
		{"ctxvalue", func(ctx context.Context) string { s, _ := ctx.Value(ctxKey{}).(string); return s }, nil},
		{"reenter", func(ctx context.Context, foo string) (string, error) {
			r, err := m.Call(ctx, "one.two", foo)
			if err != nil {
				return "", err
			}
			return "outer " + r.(string), nil
		}, []command.Option{command.WithParams("foo")}},
	}
	for _, r := range regs {
		if err := m.Register(r.name, r.fn, r.opts...); err != nil {
			t.Fatalf("Register(%q): %v", r.name, err)
		}
	}
	return m
}

func TestManagerCall(t *testing.T) {
	tests := map[string]struct {
		name        string
		args        []any
		ctx         func(context.Context) context.Context
		want        any
		wantErr     error
		wantErrText string
	}{
		"success: string command": {
			name: "one.two", args: []any{"foo"}, want: "ret foo",
		},
		"success: int command": {
			name: "cmd3", args: []any{1}, want: 1,
		},
		"success: command without result returns nil": {
			name: "empty",
		},
		"success: variadic command": {
			name: "varargs", args: []any{"one", "two", "three"}, want: []string{"two", "three"},
		},
		"success: variadic command with no trailing arguments": {
			name: "varargs", args: []any{"one"}, want: []string{},
		},
		"success: named slice type argument": {
			name: "cut", args: []any{command.CutSpec{"request.host", "response.status_code"}}, want: 2,
		},
		"success: nil for a slice parameter": {
			name: "cut", args: []any{nil}, want: 0,
		},
		"success: context reaches the command": {
			name: "ctxvalue",
			ctx:  func(ctx context.Context) context.Context { return context.WithValue(ctx, ctxKey{}, "carried") },
			want: "carried",
		},
		"success: command calls another command": {
			name: "reenter", args: []any{"foo"}, want: "outer ret foo",
		},
		"error: unknown command": {
			name: "nonexistent", wantErr: command.ErrUnknownCommand, wantErrText: "unknown command: nonexistent",
		},
		"error: too many arguments": {
			name: "one.two", args: []any{"too", "many", "args"}, wantErr: command.ErrArgumentMismatch, wantErrText: "argument mismatch",
		},
		"error: too few arguments": {
			name: "one.two", wantErr: command.ErrArgumentMismatch, wantErrText: "takes 1 argument, got 0",
		},
		"error: too few arguments for variadic command": {
			name: "varargs", wantErr: command.ErrArgumentMismatch, wantErrText: "takes at least 1 arguments, got 0",
		},
		"error: wrong argument type": {
			name: "one.two", args: []any{42}, wantErr: command.ErrArgumentMismatch, wantErrText: "int is not a string",
		},
		"error: wrong variadic element type": {
			name: "varargs", args: []any{"one", 2}, wantErr: command.ErrArgumentMismatch, wantErrText: "argument var",
		},
		"success: unnamed slice assignable to the named type": {
			name: "cut", args: []any{[]string{"request.host"}}, want: 1,
		},
		"error: named type with a different underlying type": {
			name: "one.two", args: []any{command.CutSpec{"x"}}, wantErr: command.ErrArgumentMismatch,
		},
		"error: nil for a string parameter": {
			name: "one.two", args: []any{nil}, wantErr: command.ErrArgumentMismatch, wantErrText: "nil is not a string",
		},
		"error: command error is returned as is": {
			name: "fail", wantErr: errBoom,
		},
		"error: error-only command": {
			name: "failonly", wantErr: errBoom,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := newTestManager(t)
			ctx := t.Context()
			if tt.ctx != nil {
				ctx = tt.ctx(ctx)
			}
			got, err := m.Call(ctx, tt.name, tt.args...)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) || !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("Call(%q, %v) error = %v, want %v containing %q", tt.name, tt.args, err, tt.wantErr, tt.wantErrText)
				}
				if got != nil {
					t.Errorf("Call(%q) returned %v alongside an error", tt.name, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Call(%q, %v): %v", tt.name, tt.args, err)
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Call(%q, %v) (-want +got):\n%s", tt.name, tt.args, diff)
			}
		})
	}
}

// TestCallRefusesNilContext checks that a nil context is refused with the
// same error whether or not a Runner is installed, before the Runner or the
// command runs.
func TestCallRefusesNilContext(t *testing.T) {
	tests := map[string]struct {
		runner bool
	}{
		"error: without a runner": {},
		"error: with a runner":    {runner: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := newTestManager(t)
			var runs int
			if tt.runner {
				if err := m.SetRunner(func(ctx context.Context, _ string, run func(context.Context) (any, error)) (any, error) {
					runs++
					return run(ctx)
				}); err != nil {
					t.Fatalf("SetRunner: %v", err)
				}
			}
			var nilCtx context.Context
			got, err := m.Call(nilCtx, "ctxvalue")
			if !errors.Is(err, command.ErrArgumentMismatch) || !strings.Contains(err.Error(), "ctxvalue: nil context") {
				t.Fatalf("Call(nil, %q) = %v, %v; want an error wrapping %v that names the nil context", "ctxvalue", got, err, command.ErrArgumentMismatch)
			}
			if got != nil {
				t.Errorf("Call(nil) returned %v alongside an error", got)
			}
			if runs != 0 {
				t.Errorf("the runner ran %d times for a nil context; want 0", runs)
			}
		})
	}
}

func TestManagerHelp(t *testing.T) {
	m := newTestManager(t)
	if got, want := lookup(t, m, "one.two").Help, "cmd1 help"; got != want {
		t.Errorf("Help = %q, want %q", got, want)
	}
	if got := lookup(t, m, "empty").Help; got != "" {
		t.Errorf("Help of a command registered without help = %q, want empty", got)
	}
}

// TestHelpWrapping checks the layout of help text against values recorded
// with CPython 3.13 from "\n".join(textwrap.wrap(doc.strip())), which is
// how mitmproxy builds Command.help from a docstring.
func TestHelpWrapping(t *testing.T) {
	tests := map[string]struct {
		in   string
		want string
	}{
		"success: short": {
			in:   "  cmd1 help\n",
			want: "cmd1 help",
		},
		"success: long single paragraph": {
			in:   "Save flows to a file. If the path starts with a +, flows are appended to the file, otherwise it is over-written. The file format is the native mitmproxy dump format.",
			want: "Save flows to a file. If the path starts with a +, flows are appended\nto the file, otherwise it is over-written. The file format is the\nnative mitmproxy dump format.",
		},
		"success: several paragraphs": {
			in:   "Export a flow to a path.\n\nThe format is one of the formats listed by export.formats, and the flows are written one after another in the order given.",
			want: "Export a flow to a path.  The format is one of the formats listed by\nexport.formats, and the flows are written one after another in the\norder given.",
		},
		"success: indented lines": {
			in:   "\n        Replay flows from a server.\n\n        Every flow is replayed in turn;\n            an indented continuation line keeps its leading spaces as part of the text.\n    ",
			want: "Replay flows from a server.          Every flow is replayed in turn;\nan indented continuation line keeps its leading spaces as part of the\ntext.",
		},
		"success: tabs and hyphens": {
			in:   "Mark flows.\tA well-known, mode-specific marker--the default--is used when no marker-name-that-is-rather-long-indeed is given.",
			want: "Mark flows.     A well-known, mode-specific marker--the default--is\nused when no marker-name-that-is-rather-long-indeed is given.",
		},
		"success: empty": {
			in:   "",
			want: "",
		},
		"success: whitespace only": {
			in:   " \n\t ",
			want: "",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := command.NewManager()
			if err := m.Register("helped", func(context.Context) {}, command.WithHelp(tt.in)); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, lookup(t, m, "helped").Help); diff != "" {
				t.Errorf("Help of %q (-want +got):\n%s", tt.in, diff)
			}
		})
	}
}

func TestRegisterDuplicate(t *testing.T) {
	m := command.NewManager()
	if err := m.Register("dup", func(context.Context) string { return "first" }); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	err := m.Register("dup", func(context.Context) string { return "second" })
	if !errors.Is(err, command.ErrDuplicateCommand) {
		t.Fatalf("second Register error = %v, want ErrDuplicateCommand", err)
	}
	got, err := m.Call(t.Context(), "dup")
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got != "first" {
		t.Errorf("Call(dup) = %v, want the first registration's result", got)
	}
}

func TestCommandsOrder(t *testing.T) {
	m := command.NewManager()
	names := []string{"view.flows.add", "cut", "export.file", "a.b"}
	for _, n := range names {
		if err := m.Register(n, func(context.Context) {}); err != nil {
			t.Fatalf("Register(%q): %v", n, err)
		}
	}

	var got []string
	for n, c := range m.Commands() {
		if n != c.Name {
			t.Errorf("Commands yielded key %q for command %q", n, c.Name)
		}
		got = append(got, n)
	}
	if diff := cmp.Diff(names, got); diff != "" {
		t.Errorf("Commands order (-want +got):\n%s", diff)
	}

	var first []string
	for n := range m.Commands() {
		first = append(first, n)
		break
	}
	if diff := cmp.Diff(names[:1], first); diff != "" {
		t.Errorf("Commands after break (-want +got):\n%s", diff)
	}
}

func TestManagerConcurrentUse(t *testing.T) {
	m := newTestManager(t)
	fixtures := 0
	for range m.Commands() {
		fixtures++
	}
	const workers = 8
	var wg sync.WaitGroup
	for i := range workers {
		wg.Go(func() {
			name := fmt.Sprintf("worker.%d", i)
			if err := m.Register(name, func(_ context.Context, s string) string { return name + " " + s }, command.WithParams("s")); err != nil {
				t.Errorf("Register(%q): %v", name, err)
				return
			}
			for range 100 {
				got, err := m.Call(t.Context(), name, "x")
				if err != nil || got != name+" x" {
					t.Errorf("Call(%q) = %v, %v", name, got, err)
					return
				}
				for range m.Commands() {
				}
			}
		})
	}
	wg.Wait()

	count := 0
	for range m.Commands() {
		count++
	}
	if want := fixtures + workers; count != want {
		t.Errorf("registered %d commands, want %d", count, want)
	}
}

func TestUnregister(t *testing.T) {
	m := command.NewManager()
	for _, n := range []string{"a", "b", "c"} {
		if err := m.Register(n, func(context.Context) string { return "first " + n }); err != nil {
			t.Fatalf("Register(%q): %v", n, err)
		}
	}

	if !m.Unregister("b") {
		t.Fatal("Unregister(b) = false, want true for a registered command")
	}
	if m.Unregister("b") {
		t.Error("second Unregister(b) = true, want false")
	}
	if m.Unregister("nonexistent") {
		t.Error("Unregister(nonexistent) = true, want false")
	}
	if _, err := m.Call(t.Context(), "b"); !errors.Is(err, command.ErrUnknownCommand) {
		t.Errorf("Call(b) after Unregister error = %v, want ErrUnknownCommand", err)
	}

	// The name is free again: registering it succeeds and the new function
	// is the one called; it goes to the end of the order.
	if err := m.Register("b", func(context.Context) string { return "second b" }); err != nil {
		t.Fatalf("Register(b) after Unregister: %v", err)
	}
	got, err := m.Call(t.Context(), "b")
	if err != nil || got != "second b" {
		t.Errorf("Call(b) = %v, %v; want the second registration", got, err)
	}
	var names []string
	for n := range m.Commands() {
		names = append(names, n)
	}
	if diff := cmp.Diff([]string{"a", "c", "b"}, names); diff != "" {
		t.Errorf("Commands order (-want +got):\n%s", diff)
	}
}

// runnerCall is one call a recording Runner saw.
type runnerCall struct {
	Name   string
	Result any
	Err    string
}

// TestSetRunner routes calls through a Runner, which decides the context
// the command gets and sees the result, and removes it again.
func TestSetRunner(t *testing.T) {
	tests := map[string]struct {
		name    string
		args    []any
		want    any
		wantErr error
		calls   []runnerCall
	}{
		"success: the command gets the runner's context": {
			name:  "ctxvalue",
			want:  "from runner",
			calls: []runnerCall{{Name: "ctxvalue", Result: "from runner"}},
		},
		"success: a command calling another goes through the runner twice": {
			name:  "reenter",
			args:  []any{"foo"},
			want:  "outer ret foo",
			calls: []runnerCall{{Name: "one.two", Result: "ret foo"}, {Name: "reenter", Result: "outer ret foo"}},
		},
		"error: an unknown command is looked up inside the runner": {
			name:    "nonexistent",
			wantErr: command.ErrUnknownCommand,
			calls:   []runnerCall{{Name: "nonexistent", Err: "unknown command: nonexistent"}},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := newTestManager(t)
			var calls []runnerCall
			if err := m.SetRunner(func(ctx context.Context, name string, run func(context.Context) (any, error)) (any, error) {
				res, err := run(context.WithValue(ctx, ctxKey{}, "from runner"))
				c := runnerCall{Name: name, Result: res}
				if err != nil {
					c.Err = err.Error()
				}
				calls = append(calls, c)
				return res, err
			}); err != nil {
				t.Fatalf("SetRunner: %v", err)
			}
			got, err := m.Call(t.Context(), tt.name, tt.args...)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Call(%q) error = %v, want %v", tt.name, err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Call(%q) (-want +got):\n%s", tt.name, diff)
			}
			if diff := cmp.Diff(tt.calls, calls); diff != "" {
				t.Errorf("runner calls (-want +got):\n%s", diff)
			}
		})
	}
}

// TestSetRunnerRefusesReplacement checks that a Runner, once installed,
// stays: a second SetRunner, with another Runner or with nil, is refused
// and calls keep going through the first one.
func TestSetRunnerRefusesReplacement(t *testing.T) {
	tests := map[string]struct {
		second command.Runner
	}{
		"error: another runner": {
			second: func(ctx context.Context, _ string, run func(context.Context) (any, error)) (any, error) {
				return run(context.WithValue(ctx, ctxKey{}, "second"))
			},
		},
		"error: nil runner": {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := newTestManager(t)
			first := func(ctx context.Context, _ string, run func(context.Context) (any, error)) (any, error) {
				return run(context.WithValue(ctx, ctxKey{}, "first"))
			}
			if err := m.SetRunner(first); err != nil {
				t.Fatalf("first SetRunner: %v", err)
			}
			if err := m.SetRunner(tt.second); !errors.Is(err, command.ErrRunnerSet) {
				t.Fatalf("second SetRunner error = %v, want %v", err, command.ErrRunnerSet)
			}
			got, err := m.Call(t.Context(), "ctxvalue")
			if err != nil || got != "first" {
				t.Errorf("Call after a refused SetRunner = %v, %v; want %q from the first runner", got, err, "first")
			}
		})
	}
}

// TestCallPassesFlows checks that flow and flow-list arguments reach the
// command as the very values the caller passed, with and without a Runner,
// and that values that are not flows of the declared shape are refused.
func TestCallPassesFlows(t *testing.T) {
	h := flow.NewHTTPFlow(nil, nil, true)
	tc := flow.NewTCPFlow(nil, nil, true)
	tests := map[string]struct {
		name        string
		args        []any
		want        []flow.Flow
		wantErr     error
		wantErrText string
	}{
		"success: flow list of mixed kinds": {
			name: "flows.take", args: []any{[]flow.Flow{h, tc}}, want: []flow.Flow{h, tc},
		},
		"success: empty flow list": {
			name: "flows.take", args: []any{[]flow.Flow{}}, want: []flow.Flow{},
		},
		"success: nil flow list": {
			name: "flows.take", args: []any{nil}, want: nil,
		},
		"success: concrete flow for a single flow parameter": {
			name: "flow.take", args: []any{h}, want: []flow.Flow{h},
		},
		"success: variadic flows": {
			name: "flow.each", args: []any{tc, h}, want: []flow.Flow{tc, h},
		},
		"error: concrete flow slice for a flow list parameter": {
			name: "flows.take", args: []any{[]*flow.HTTPFlow{h}}, wantErr: command.ErrArgumentMismatch, wantErrText: "argument flows: []*flow.HTTPFlow is not a []flow.Flow",
		},
		"error: single flow for a flow list parameter": {
			name: "flows.take", args: []any{h}, wantErr: command.ErrArgumentMismatch, wantErrText: "argument flows",
		},
		"error: flow list for a single flow parameter": {
			name: "flow.take", args: []any{[]flow.Flow{h}}, wantErr: command.ErrArgumentMismatch, wantErrText: "argument f",
		},
		"error: string for a flow parameter": {
			name: "flow.take", args: []any{"@all"}, wantErr: command.ErrArgumentMismatch, wantErrText: "string is not a flow.Flow",
		},
	}
	for name, tt := range tests {
		for _, runner := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/runner=%t", name, runner), func(t *testing.T) {
				m := command.NewManager()
				var got []flow.Flow
				regs := []struct {
					name   string
					fn     any
					params []string
				}{
					{"flows.take", func(_ context.Context, flows []flow.Flow) { got = flows }, []string{"flows"}},
					{"flow.take", func(_ context.Context, f flow.Flow) { got = []flow.Flow{f} }, []string{"f"}},
					{"flow.each", func(_ context.Context, fs ...flow.Flow) { got = fs }, []string{"fs"}},
				}
				for _, r := range regs {
					if err := m.Register(r.name, r.fn, command.WithParams(r.params...)); err != nil {
						t.Fatalf("Register(%q): %v", r.name, err)
					}
				}
				var runs int
				if runner {
					if err := m.SetRunner(func(ctx context.Context, _ string, run func(context.Context) (any, error)) (any, error) {
						runs++
						return run(ctx)
					}); err != nil {
						t.Fatalf("SetRunner: %v", err)
					}
				}
				_, err := m.Call(t.Context(), tt.name, tt.args...)
				if runner && runs != 1 {
					t.Errorf("the runner ran %d times; want 1", runs)
				}
				if tt.wantErr != nil {
					if !errors.Is(err, tt.wantErr) || !strings.Contains(err.Error(), tt.wantErrText) {
						t.Fatalf("Call(%q) error = %v, want %v containing %q", tt.name, err, tt.wantErr, tt.wantErrText)
					}
					return
				}
				if err != nil {
					t.Fatalf("Call(%q): %v", tt.name, err)
				}
				if len(got) != len(tt.want) || (got == nil) != (tt.want == nil) {
					t.Fatalf("Call(%q) passed %d flows (nil %t), want %d (nil %t)", tt.name, len(got), got == nil, len(tt.want), tt.want == nil)
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("flow %d: got %p, want the caller's flow %p", i, got[i], tt.want[i])
					}
				}
			})
		}
	}
}
