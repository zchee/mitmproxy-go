// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package comment

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

type updates struct{ record func([]flow.Flow) }

func (u *updates) Update(_ context.Context, flows []flow.Flow) error {
	u.record(flows)
	return nil
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestComment(t *testing.T) {
	tests := map[string]struct {
		flows   func() []flow.Flow
		comment string
	}{
		"test_comment":         {func() []flow.Flow { return []flow.Flow{testflow.TFlow()} }, "foo"},
		"all flow types":       {testflow.TFlows, "a comment\nwith multiple lines"},
		"empty flow selection": {func() []flow.Flow { return nil }, "foo"},
		"duplicate flow": {func() []flow.Flow {
			f := testflow.TFlow()
			return []flow.Flow{f, f}
		}, "duplicate"},
		"clear comment": {func() []flow.Flow {
			f := testflow.TFlow()
			f.Comment = "previous"
			return []flow.Flow{f}
		}, ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			active := false
			manager := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{
				OnDispatchStart: func() { active = true }, OnDispatchEnd: func() { active = false },
			})
			defer manager.Close()
			c := New(manager)
			must(t, manager.Add(t.Context(), c))
			flows := tt.flows()
			calls := 0
			must(t, manager.Add(t.Context(), &updates{record: func(updated []flow.Flow) {
				calls++
				if !active {
					t.Fatal("update fired outside dispatch")
				}
				if len(updated) != len(flows) {
					t.Fatal("changed flow selection")
				}
				for i, f := range updated {
					if f != flows[i] {
						t.Fatal("changed flow order or identity")
					}
					if diff := cmp.Diff(tt.comment, f.Common().Comment); diff != "" {
						t.Fatal(diff)
					}
				}
			}}))
			_, err := manager.Commands().Call(t.Context(), "flow.comment", flows, tt.comment)
			must(t, err)
			if calls != 1 {
				t.Fatal("expected one update, including for an empty selection")
			}
		})
	}
}

func TestContract(t *testing.T) {
	manager := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{})
	defer manager.Close()
	c := New(manager)
	must(t, manager.Add(t.Context(), c))
	if len(manager.Options().Items()) != 0 {
		t.Fatal("unexpected option")
	}
	count := 0
	for name, cmd := range manager.Commands().Commands() {
		count++
		if name != "flow.comment" || cmd.SignatureHelp() != "flow.comment flow comment" || cmd.Help != "Add a comment to a flow" {
			t.Fatalf("unexpected command: %s %s %s", name, cmd.SignatureHelp(), cmd.Help)
		}
	}
	if count != 1 {
		t.Fatal("missing command")
	}
	must(t, manager.Do(t.Context(), func(ctx context.Context) error {
		f := testflow.TFlow()
		if err := c.Set(ctx, []flow.Flow{f}, "direct"); err != nil {
			return err
		}
		if diff := cmp.Diff("direct", f.Comment); diff != "" {
			t.Fatal(diff)
		}
		return nil
	}))
}
