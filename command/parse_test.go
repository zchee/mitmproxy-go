// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package command_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

// Upstream test_command.py mapping:
// TestCommand.test_typecheck -> TestRegisterSignature.
// TestCommand.test_varargs -> TestStringCallsUpstream and TestRegisterSignature.
// TestCommand.test_call -> TestStringCallsUpstream; a declared str returning an
// int cannot compile in Go, so invalid Data cells exercise return validation.
// TestCommand.test_parse_partial -> TestParsePartialUpstream (every input).
// test_simple -> TestExecuteUpstream, TestDumpUpstream, TestManagerCall.
// test_typename -> TestTypeIdentities, TestTypeFor; missing annotations have no
// Go counterpart because every Go parameter has a compile-time type.
// test_parsearg -> TestTypesUpstream, TestStringCallsUpstream; unsupported types
// are rejected at registration, covered by TestRegisterSignature.
// test_collect_commands -> not applicable: Loader.AddCommand registers Go
// functions explicitly; there is no getattr or decorator discovery.
// test_decorator -> TestExecuteUpstream and TestExecuteDispatchDomain; explicit
// registration replaces Python decorators.
// test_verify_arg_signature -> TestManagerCall and TestStringCallsUpstream.

func newParsingManager(t *testing.T) *command.Manager {
	t.Helper()
	m := newTestManager(t)
	regs := map[string]struct {
		fn    any
		names []string
	}{
		"cmd1":       {func(_ context.Context, foo string) string { return "ret " + foo }, []string{"foo"}},
		"cmd4":       {func(_ context.Context, a int, b string, c command.Path) string { return "ok" }, []string{"a", "b", "c"}},
		"subcommand": {func(_ context.Context, cmd command.Cmd, args ...command.CmdArgs) string { return "ok" }, []string{"cmd", "args"}},
		"flow":       {func(_ context.Context, f flow.Flow, s string) {}, []string{"f", "s"}},
	}
	for name, r := range regs {
		if err := m.Register(name, r.fn, command.WithParams(r.names...)); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func TestParsePartialUpstream(t *testing.T) {
	type token struct {
		value, typ string
		valid      bool
	}
	space := token{" ", "Space", true}
	tests := map[string]struct {
		parsed []token
		remain []string
	}{
		"foo bar":               {[]token{{"foo", "Cmd", false}, space, {"bar", "Unknown", false}}, nil},
		"cmd1 'bar":             {[]token{{"cmd1", "Cmd", true}, space, {"'bar", "Str", true}}, nil},
		"a":                     {[]token{{"a", "Cmd", false}}, nil},
		"":                      {nil, []string{":Cmd", ":Arg"}},
		"cmd3 1":                {[]token{{"cmd3", "Cmd", true}, space, {"1", "Int", true}}, nil},
		"cmd3 ":                 {[]token{{"cmd3", "Cmd", true}, space}, []string{"foo:Int"}},
		"subcommand ":           {[]token{{"subcommand", "Cmd", true}, space}, []string{"cmd:Cmd", "*args:Arg"}},
		"varargs one":           {[]token{{"varargs", "Cmd", true}, space, {"one", "Str", true}}, []string{"*var:Str"}},
		"varargs one two three": {[]token{{"varargs", "Cmd", true}, space, {"one", "Str", true}, space, {"two", "Str", true}, space, {"three", "Str", true}}, nil},
		"subcommand cmd3 ":      {[]token{{"subcommand", "Cmd", true}, space, {"cmd3", "Cmd", true}, space}, []string{"foo:Int"}},
		"cmd4":                  {[]token{{"cmd4", "Cmd", true}}, []string{"a:Int", "b:Str", "c:Path"}},
		"cmd4 ":                 {[]token{{"cmd4", "Cmd", true}, space}, []string{"a:Int", "b:Str", "c:Path"}},
		"cmd4 1":                {[]token{{"cmd4", "Cmd", true}, space, {"1", "Int", true}}, []string{"b:Str", "c:Path"}},
		"flow":                  {[]token{{"flow", "Cmd", true}}, []string{"f:Flow", "s:Str"}},
		"flow ":                 {[]token{{"flow", "Cmd", true}, space}, []string{"f:Flow", "s:Str"}},
		"flow x":                {[]token{{"flow", "Cmd", true}, space, {"x", "Flow", false}}, []string{"s:Str"}},
		"flow x ":               {[]token{{"flow", "Cmd", true}, space, {"x", "Flow", false}, space}, []string{"s:Str"}},
		`flow "one two`:         {[]token{{"flow", "Cmd", true}, space, {`"one two`, "Flow", false}}, []string{"s:Str"}},
		`flow "three four"`:     {[]token{{"flow", "Cmd", true}, space, {`"three four"`, "Flow", false}}, []string{"s:Str"}},
		"spaces '    '":         {[]token{{"spaces", "Cmd", false}, space, {"'    '", "Unknown", false}}, nil},
		`spaces2 "    "`:        {[]token{{"spaces2", "Cmd", false}, space, {`"    "`, "Unknown", false}}, nil},
		`"abc"`:                 {[]token{{`"abc"`, "Cmd", false}}, nil},
		"'def'":                 {[]token{{"'def'", "Cmd", false}}, nil},
		`cmd10 'a' "b" c`:       {[]token{{"cmd10", "Cmd", false}, space, {"'a'", "Unknown", false}, space, {`"b"`, "Unknown", false}, space, {"c", "Unknown", false}}, nil},
		`cmd11 'a "b" c'`:       {[]token{{"cmd11", "Cmd", false}, space, {`'a "b" c'`, "Unknown", false}}, nil},
		`cmd12 "a 'b' c"`:       {[]token{{"cmd12", "Cmd", false}, space, {`"a 'b' c"`, "Unknown", false}}, nil},
		"    spaces_at_the_beginning_are_not_stripped":                          {[]token{{"    ", "Space", true}, {"spaces_at_the_beginning_are_not_stripped", "Cmd", false}}, nil},
		"    spaces_at_the_beginning_are_not_stripped neither_at_the_end      ": {[]token{{"    ", "Space", true}, {"spaces_at_the_beginning_are_not_stripped", "Cmd", false}, space, {"neither_at_the_end", "Unknown", false}, {"      ", "Space", true}}, nil},
	}
	for input, tt := range tests {
		t.Run(input, func(t *testing.T) {
			m := newParsingManager(t)
			parsed, remain := m.ParsePartial(t.Context(), input)
			var got []token
			for _, p := range parsed {
				got = append(got, token{p.Value, typeID(p.Type), p.Valid})
			}
			if diff := cmp.Diff(tt.parsed, got, cmp.AllowUnexported(token{}), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("tokens (-want +got):\n%s", diff)
			}
			var params []string
			for _, p := range remain {
				params = append(params, p.String()+":"+typeID(p.Type))
			}
			if diff := cmp.Diff(tt.remain, params, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("remaining parameters (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExecuteUpstream(t *testing.T) {
	tests := map[string]struct {
		input   string
		want    any
		wantErr error
	}{
		"unquoted":      {"one.two foo", "ret foo", nil},
		"double quoted": {`one.two "foo"`, "ret foo", nil},
		"single quoted": {"one.two 'foo bar'", "ret foo bar", nil},
		"unknown":       {"nonexistent", nil, command.ErrUnknownCommand},
		"empty":         {"", nil, command.ErrInvalidArgument},
		"whitespace":    {" \t ", nil, command.ErrInvalidArgument},
		"arity":         {"one.two too many args", nil, command.ErrArgumentMismatch},
		"backslash":     {`\`, nil, command.ErrUnknownCommand},
		"no return":     {"empty", nil, nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := newParsingManager(t).Execute(t.Context(), tt.input)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Execute(%q) error = %v, want %v", tt.input, err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestStringCallsUpstream(t *testing.T) {
	tests := map[string]struct {
		name    string
		args    []string
		want    any
		wantErr error
	}{
		"string":           {"cmd1", []string{"foo"}, "ret foo", nil},
		"integer":          {"cmd3", []string{"1"}, 1, nil},
		"bad integer":      {"cmd3", []string{"foo"}, nil, command.ErrInvalidArgument},
		"variadic":         {"varargs", []string{"one", "two", "three"}, []string{"two", "three"}, nil},
		"no variadic args": {"varargs", []string{"one"}, []string{}, nil},
		"missing argument": {"cmd1", nil, nil, command.ErrArgumentMismatch},
		"extra argument":   {"cmd1", []string{"one", "two"}, nil, command.ErrArgumentMismatch},
		"invalid return":   {"bad.data", nil, nil, command.ErrInvalidArgument},
		"unknown":          {"missing", nil, nil, command.ErrUnknownCommand},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := newParsingManager(t)
			if err := m.Register("bad.data", func(context.Context) command.Data { return command.Data{{1}} }); err != nil {
				t.Fatal(err)
			}
			got, err := m.CallStrings(t.Context(), tt.name, tt.args)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("CallStrings(%q) error = %v, want %v", tt.name, err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestDumpUpstream(t *testing.T) {
	m := command.NewManager()
	if err := m.Register("one.two", func(_ context.Context, foo string) string { return foo }, command.WithParams("foo"), command.WithHelp("cmd1 help")); err != nil {
		t.Fatal(err)
	}
	if err := m.Register("empty", func(context.Context) {}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := m.Dump(&out); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff("empty \n\n# cmd1 help\none.two foo -> str\n\n", out.String()); diff != "" {
		t.Error(diff)
	}
}

func TestExecuteRunnerHold(t *testing.T) {
	m := command.NewManager()
	type frameKey struct{}
	var events []string
	var active bool
	if err := m.SetRunner(func(ctx context.Context, name string, run func(context.Context) (any, error)) (any, error) {
		inside, _ := ctx.Value(frameKey{}).(bool)
		if inside != active {
			t.Fatalf("runner %q received stale or missing frame: inside=%t active=%t", name, inside, active)
		}
		if !inside {
			active = true
			events = append(events, "acquire")
			defer func() { active = false; events = append(events, "release") }()
		}
		events = append(events, "run "+name)
		return run(context.WithValue(ctx, frameKey{}, true))
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Register("choices", func(ctx context.Context) []string {
		if !active {
			t.Fatal("choice parsing ran outside hold")
		}
		events = append(events, "choices")
		return []string{"one"}
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Register("choose", func(ctx context.Context, value string) string {
		events = append(events, "choose")
		return value
	}, command.WithParams("value"), command.WithArgument("value", command.Choice("choices"))); err != nil {
		t.Fatal(err)
	}
	got, err := m.Execute(t.Context(), "choose one")
	if err != nil || got != "one" {
		t.Fatalf("Execute = %v, %v", got, err)
	}
	if events[0] != "acquire" || events[len(events)-1] != "release" {
		t.Fatal(events)
	}
	acquires, chooses := 0, 0
	for _, event := range events {
		if event == "acquire" {
			acquires++
		}
		if event == "run choose" {
			chooses++
		}
	}
	if acquires != 1 {
		t.Errorf("ParsePartial, argument parsing, and execution must share one outer hold, got %d: %v", acquires, events)
	}
	if chooses != 2 {
		t.Errorf("Execute must enter its outer hold then call Manager.Call for choose, got %d runner calls: %v", chooses, events)
	}
}

func TestExecuteDispatchDomain(t *testing.T) {
	m := command.NewManager()
	acquires := 0
	am := addon.NewManager(options.NewManager(), m, addon.Config{OnDispatchStart: func() { acquires++ }})
	t.Cleanup(am.Close)
	check := func(ctx context.Context) {
		_, err := addon.Concurrent(ctx, func(context.Context) error { t.Fatal("synchronous command released dispatch"); return nil })
		if !errors.Is(err, addon.ErrSyncContext) {
			t.Fatalf("Concurrent error = %v", err)
		}
	}
	if err := m.Register("choices", func(ctx context.Context) []string { check(ctx); return []string{"one"} }); err != nil {
		t.Fatal(err)
	}
	if err := m.Register("choose", func(ctx context.Context, value string) (string, error) {
		check(ctx)
		var got any
		err := am.Do(ctx, func(ctx context.Context) error { var err error; got, err = m.Call(ctx, "echo", value); return err })
		return fmt.Sprint(got), err
	}, command.WithParams("value"), command.WithArgument("value", command.Choice("choices"))); err != nil {
		t.Fatal(err)
	}
	if err := m.Register("echo", func(ctx context.Context, value string) string { check(ctx); return value }); err != nil {
		t.Fatal(err)
	}
	got, err := m.Execute(t.Context(), "choose one")
	if err != nil || got != "one" {
		t.Fatalf("Execute = %v, %v", got, err)
	}
	if acquires != 1 {
		t.Fatalf("choice parsing escaped outer dispatch hold: acquired %d times", acquires)
	}
}

func TestStringCallsNilContext(t *testing.T) {
	tests := map[string]struct{ execute bool }{"execute": {true}, "call strings": {false}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := newParsingManager(t)
			if err := m.SetRunner(func(context.Context, string, func(context.Context) (any, error)) (any, error) {
				t.Fatal("runner invoked with nil context")
				return nil, nil
			}); err != nil {
				t.Fatal(err)
			}
			var ctx context.Context
			var err error
			if tt.execute {
				_, err = m.Execute(ctx, "cmd1 foo")
			} else {
				_, err = m.CallStrings(ctx, "cmd1", []string{"foo"})
			}
			if !errors.Is(err, command.ErrArgumentMismatch) || !strings.Contains(err.Error(), "nil context") {
				t.Fatalf("nil context error = %v", err)
			}
		})
	}
}
