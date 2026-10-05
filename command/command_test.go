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
		"error: flow identity has no Go binding yet": {
			name:    "flow",
			fn:      func(_ context.Context, arg string) {},
			opts:    []command.Option{command.WithParams("arg"), command.WithArgument("arg", command.FlowType)},
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
		{"ctxnil", func(ctx context.Context) bool { return ctx == nil }, nil},
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
		"success: nil context is passed as nil": {
			name: "ctxnil",
			ctx:  func(context.Context) context.Context { return nil },
			want: true,
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

func TestManagerHelp(t *testing.T) {
	m := newTestManager(t)
	if got, want := lookup(t, m, "one.two").Help, "cmd1 help"; got != want {
		t.Errorf("Help = %q, want %q", got, want)
	}
	if got := lookup(t, m, "empty").Help; got != "" {
		t.Errorf("Help of a command registered without help = %q, want empty", got)
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
	if want := 10 + workers; count != want {
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
