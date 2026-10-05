// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package command_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
)

func TestIntegerLimits(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	overflow, underflow := "9223372036854775808", "-9223372036854775809"
	if strconv.IntSize == 32 {
		overflow, underflow = "2147483648", "-2147483649"
	}
	tests := map[string]struct {
		input string
		want  int
		bad   bool
	}{
		"maximum":   {strconv.Itoa(maxInt), maxInt, false},
		"minimum":   {strconv.Itoa(-maxInt - 1), -maxInt - 1, false},
		"overflow":  {overflow, 0, true},
		"underflow": {underflow, 0, true},
	}
	m := command.NewManager()
	if err := m.Register("number", func(_ context.Context, n int) int { return n }, command.WithParams("value")); err != nil {
		t.Fatal(err)
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := m.CallStrings(t.Context(), "number", []string{tt.input})
			if tt.bad {
				if !errors.Is(err, command.ErrInvalidArgument) || !strings.Contains(err.Error(), tt.input) || !strings.Contains(err.Error(), "value") {
					t.Fatalf("overflow lacks argument context: %v", err)
				}
			} else if err != nil || got != tt.want {
				t.Fatalf("number(%q) = %v, %v; want %d", tt.input, got, err, tt.want)
			}
		})
	}
}

func TestStrictScalarValidation(t *testing.T) {
	tests := map[string]struct {
		typ   command.Type
		value any
		want  bool
	}{
		"integer":                 {command.IntType, 1, true},
		"integer rejects boolean": {command.IntType, true, false},
		"boolean":                 {command.BoolType, true, true},
		"boolean rejects integer": {command.BoolType, 1, false},
		"boolean rejects float":   {command.BoolType, 0.0, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tt.typ.IsValid(t.Context(), command.NewManager(), tt.value); got != tt.want {
				t.Errorf("IsValid(%v) = %t, want %t", tt.value, got, tt.want)
			}
		})
	}
}

func TestSurrogateEscapeRejected(t *testing.T) {
	tests := map[string]struct{ input string }{
		"high surrogate": {`\U0000D800`},
		"low surrogate":  {`\U0000DFFF`},
		"surrogate pair": {`\U0000D83D\U0000DE00`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := command.StrType.Parse(t.Context(), command.NewManager(), tt.input); err == nil {
				t.Fatalf("accepted non-scalar escape %q", tt.input)
			}
		})
	}
}

func TestParsePartialRefreshesChoices(t *testing.T) {
	m := command.NewManager()
	choices := []string{"one"}
	if err := m.Register("choices", func(context.Context) []string { return choices }); err != nil {
		t.Fatal(err)
	}
	if err := m.Register("choose", func(context.Context, string) {}, command.WithParams("choice"), command.WithArgument("choice", command.Choice("choices"))); err != nil {
		t.Fatal(err)
	}
	first, _ := m.ParsePartial(t.Context(), "choose one")
	choices = []string{"two"}
	second, _ := m.ParsePartial(t.Context(), "choose one")
	if !first[2].Valid || second[2].Valid {
		t.Fatalf("partial parsing retained stale choice validity: first=%v second=%v", first, second)
	}
}

func TestDynamicTypeResultOwnership(t *testing.T) {
	m := command.NewManager()
	choices := []string{"one", "two"}
	if err := m.Register("choices", func(context.Context) []string { return choices }); err != nil {
		t.Fatal(err)
	}
	got, err := command.Choice("choices").Completion(t.Context(), m, "")
	if err != nil {
		t.Fatal(err)
	}
	got[0] = "changed"
	if diff := cmp.Diff([]string{"one", "two"}, choices); diff != "" {
		t.Errorf("choice completion shares provider storage: %s", diff)
	}
	original := flow.NewHTTPFlow(nil, nil, false)
	flows := []flow.Flow{original}
	if err := m.Register("view.flows.resolve", func(context.Context, string) []flow.Flow { return flows }); err != nil {
		t.Fatal(err)
	}
	parsed, err := command.FlowsType.Parse(t.Context(), m, "@all")
	if err != nil {
		t.Fatal(err)
	}
	parsed.([]flow.Flow)[0] = nil
	if !slices.Equal(flows, []flow.Flow{original}) {
		t.Fatal("parsed flow slice shares resolver storage")
	}
}
