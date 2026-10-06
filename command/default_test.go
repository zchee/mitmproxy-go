// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package command_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/command"
)

func TestCommandDefaultArguments(t *testing.T) {
	tests := map[string]struct {
		native  []any
		strings []string
		line    string
		want    string
		wantErr error
	}{
		"success: native omitted defaults":       {native: []any{7}, want: `7:true:\x41`},
		"success: native explicit first default": {native: []any{7, false}, want: `7:false:\x41`},
		"success: native explicit defaults":      {native: []any{7, false, "override"}, want: "7:false:override"},
		"success: string omitted defaults":       {strings: []string{"7"}, want: `7:true:\x41`},
		"success: string explicit first default": {strings: []string{"7", "false"}, want: `7:false:\x41`},
		"success: string parsed override":        {strings: []string{"7", "false", `\x42`}, want: "7:false:B"},
		"success: execute omitted defaults":      {line: "defaults 7", want: `7:true:\x41`},
		"success: execute explicit defaults":     {line: `defaults 7 false "\x42"`, want: "7:false:B"},
		"error: native missing required":         {wantErr: command.ErrArgumentMismatch},
		"error: native extra argument":           {native: []any{7, true, "override", "extra"}, wantErr: command.ErrArgumentMismatch},
		"error: native explicit wrong type":      {native: []any{7, "false"}, wantErr: command.ErrArgumentMismatch},
		"error: string missing required":         {strings: []string{}, wantErr: command.ErrArgumentMismatch},
		"error: string extra argument":           {strings: []string{"7", "true", "override", "extra"}, wantErr: command.ErrArgumentMismatch},
		"error: string malformed override":       {strings: []string{"7", "invalid"}, wantErr: command.ErrInvalidArgument},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := command.NewManager()
			fn := func(_ context.Context, count int, enabled bool, suffix string) string {
				return fmt.Sprintf("%d:%t:%s", count, enabled, suffix)
			}
			if err := m.Register("defaults", fn, command.WithDefault("enabled", true), command.WithDefault("suffix", `\x41`), command.WithParams("count", "enabled", "suffix")); err != nil {
				t.Fatal(err)
			}
			var got any
			var err error
			switch {
			case tt.line != "":
				got, err = m.Execute(t.Context(), tt.line)
			case tt.strings != nil:
				got, err = m.CallStrings(t.Context(), "defaults", tt.strings)
			default:
				got, err = m.Call(t.Context(), "defaults", tt.native...)
			}
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("default call = %v, %v; want %v", got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(any(tt.want), got); diff != "" {
				t.Fatalf("default arguments (-want +got):\n%s", diff)
			}
			c := lookup(t, m, "defaults")
			if c.SignatureHelp() != "defaults count enabled suffix -> str" || c.Params[1].Variadic {
				t.Fatalf("default changed signature: %q, %+v", c.SignatureHelp(), c.Params)
			}
		})
	}
}

func TestCommandDefaultRegistration(t *testing.T) {
	tests := map[string]struct {
		fn      any
		opts    []command.Option
		wantErr bool
	}{
		"error: unknown parameter": {
			fn: func(context.Context, bool) {}, opts: []command.Option{command.WithDefault("missing", true)}, wantErr: true,
		},
		"error: default has wrong type": {
			fn: func(context.Context, bool) {}, opts: []command.Option{command.WithDefault("arg0", "true")}, wantErr: true,
		},
		"error: nil is not bool": {
			fn: func(context.Context, bool) {}, opts: []command.Option{command.WithDefault("arg0", nil)}, wantErr: true,
		},
		"error: required parameter after default": {
			fn: func(context.Context, bool, string) {}, opts: []command.Option{command.WithDefault("arg0", true)}, wantErr: true,
		},
		"error: variadic parameter cannot have a default": {
			fn: func(context.Context, ...string) {}, opts: []command.Option{command.WithDefault("arg0", "value")}, wantErr: true,
		},
		"success: trailing bool": {
			fn: func(context.Context, int, bool) {}, opts: []command.Option{command.WithDefault("arg1", true)},
		},
		"success: all fixed parameters default": {
			fn: func(context.Context, int, bool) {}, opts: []command.Option{command.WithDefault("arg0", 7), command.WithDefault("arg1", true)},
		},
		"success: default before variadic": {
			fn: func(context.Context, bool, ...string) {}, opts: []command.Option{command.WithDefault("arg0", true)},
		},
		"success: nil byte slice": {
			fn: func(context.Context, []byte) {}, opts: []command.Option{command.WithDefault("arg0", nil)},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := command.NewManager().Register("defaults", tt.fn, tt.opts...)
			if tt.wantErr {
				if !errors.Is(err, command.ErrSignature) {
					t.Fatalf("registration = %v, want ErrSignature", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCommandDefaultBeforeVariadic(t *testing.T) {
	tests := map[string]struct {
		args []any
		want []string
	}{
		"success: omitted fixed and variadic": {want: []string{"default"}},
		"success: explicit fixed":             {args: []any{"explicit"}, want: []string{"explicit"}},
		"success: fixed and variadic":         {args: []any{"explicit", "extra", "more"}, want: []string{"explicit", "extra", "more"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := command.NewManager()
			fn := func(_ context.Context, first string, extra ...string) []string {
				return append([]string{first}, extra...)
			}
			if err := m.Register("defaults", fn, command.WithParams("first", "extra"), command.WithDefault("first", "default")); err != nil {
				t.Fatal(err)
			}
			got, err := m.Call(t.Context(), "defaults", tt.args...)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(any(tt.want), got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestCommandDefaultNil(t *testing.T) {
	tests := map[string]struct{ strings bool }{"success: native nil default": {}, "success: string nil default": {strings: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := command.NewManager()
			if err := m.Register("defaults", func(_ context.Context, payload []byte) []byte { return payload }, command.WithDefault("arg0", nil)); err != nil {
				t.Fatal(err)
			}
			var got any
			var err error
			if tt.strings {
				got, err = m.CallStrings(t.Context(), "defaults", nil)
			} else {
				got, err = m.Call(t.Context(), "defaults")
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(any([]byte(nil)), got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
