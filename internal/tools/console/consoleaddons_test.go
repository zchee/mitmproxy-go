// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func TestConsoleOptions(t *testing.T) {
	t.Run("options", func(t *testing.T) {
		tests := map[string]struct {
			typ     options.Type
			def     any
			help    string
			choices []string
		}{
			"console_default_contentview":     {options.TypeStr, "auto", "The default content view mode.", nil},
			"console_eventlog_verbosity":      {options.TypeStr, "info", "EventLog verbosity.", []string{"error", "warn", "info", "alert", "debug"}},
			"console_flowlist_layout":         {options.TypeStr, "default", "Set the flowlist layout", []string{"default", "list", "table"}},
			"console_focus_follow":            {options.TypeBool, false, "Focus follows new flows.", nil},
			"console_layout":                  {options.TypeStr, "single", "Console layout.", []string{"horizontal", "single", "vertical"}},
			"console_layout_headers":          {options.TypeBool, true, "Show layout component headers", nil},
			"console_mouse":                   {options.TypeBool, true, "Console mouse interaction.", nil},
			"console_palette":                 {options.TypeStr, "solarized_dark", "Color palette.", []string{"dark", "light", "lowdark", "lowlight", "solarized_dark", "solarized_light"}},
			"console_palette_transparent":     {options.TypeBool, true, "Set transparent background for palette.", nil},
			"console_quickhelp_visible":       {options.TypeBool, true, "Show the quick help bar at the bottom of the console.", nil},
			"console_strip_trailing_newlines": {options.TypeBool, false, "Strip trailing newlines from edited request/response bodies.", nil},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				b, _ := testBridge(t)
				mustConsole(t, b.cfg.Master.Addons.Add(t.Context(), &ConsoleAddon{bridge: b}))
				option, ok := b.cfg.Master.Options.Lookup(name)
				if !ok {
					t.Fatalf("console option %q is missing", name)
				}
				if option.Type() != test.typ || option.Help() != test.help {
					t.Fatalf("%s metadata type/help = %v/%q, want %v/%q", name, option.Type(), option.Help(), test.typ, test.help)
				}
				if diff := cmp.Diff(test.def, option.Default()); diff != "" {
					t.Fatal("default mismatch (-want +got): " + diff)
				}
				choices := test.choices
				if name == "console_default_contentview" {
					choices = b.cfg.Registry.AvailableViews()
				}
				if diff := cmp.Diff(choices, option.Choices()); diff != "" {
					t.Fatal("choices mismatch (-want +got): " + diff)
				}
			})
		}
	})
	t.Run("preservation", func(t *testing.T) {
		t.Run("view_focus_follow", func(t *testing.T) {
			b, _ := testBridge(t)
			before, ok := b.cfg.Master.Options.Lookup("console_focus_follow")
			if !ok {
				t.Fatal("View did not register focus-follow before ConsoleAddon")
			}
			mustConsole(t, b.cfg.Master.Addons.Add(t.Context(), &ConsoleAddon{bridge: b}))
			after, _ := b.cfg.Master.Options.Lookup("console_focus_follow")
			if before.Type() != after.Type() || before.Help() != after.Help() || !cmp.Equal(before.Default(), after.Default()) || !cmp.Equal(before.Choices(), after.Choices()) {
				t.Fatal("console re-registration changed View's option contract")
			}
			first, second := testflow.TFlow(), testflow.TFlow()
			mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error {
				b.cfg.View.Add(ctx, []flow.Flow{first})
				if err := b.cfg.Master.Options.Update(ctx, map[string]any{"console_focus_follow": true}); err != nil {
					return err
				}
				b.cfg.View.Add(ctx, []flow.Flow{second})
				if focused := b.cfg.View.Focus.Flow(); focused == nil || focused.Common().ID != second.ID {
					t.Fatal("View no longer owns focus-follow behavior")
				}
				return nil
			}))
		})
	})
}
