// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/options"
)

// ConsoleAddon integrates console configuration with the dispatch-owned runtime.
// A standalone value can register options without starting a terminal.
type ConsoleAddon struct{ bridge *Bridge } //nolint:revive // Keep upstream's addon name for composed registry consumers.

// Load registers console option metadata, preserving View's focus-follow owner.
func (a *ConsoleAddon) Load(ctx context.Context, loader *addon.Loader) error {
	registry := contentviews.NewRegistry()
	if a.bridge != nil {
		registry = a.bridge.cfg.Registry
	}
	for _, spec := range []struct {
		name    string
		typ     options.Type
		def     any
		help    string
		choices []string
	}{
		{"console_default_contentview", options.TypeStr, "auto", "The default content view mode.", registry.AvailableViews()},
		{"console_eventlog_verbosity", options.TypeStr, "info", "EventLog verbosity.", []string{"error", "warn", "info", "alert", "debug"}},
		{"console_layout", options.TypeStr, "single", "Console layout.", []string{"horizontal", "single", "vertical"}},
		{"console_layout_headers", options.TypeBool, true, "Show layout component headers", nil},
		{"console_focus_follow", options.TypeBool, false, "Focus follows new flows.", nil},
		{"console_palette", options.TypeStr, "solarized_dark", "Color palette.", []string{"dark", "light", "lowdark", "lowlight", "solarized_dark", "solarized_light"}},
		{"console_palette_transparent", options.TypeBool, true, "Set transparent background for palette.", nil},
		{"console_mouse", options.TypeBool, true, "Console mouse interaction.", nil},
		{"console_flowlist_layout", options.TypeStr, "default", "Set the flowlist layout", []string{"default", "list", "table"}},
		{"console_strip_trailing_newlines", options.TypeBool, false, "Strip trailing newlines from edited request/response bodies.", nil},
		{"console_quickhelp_visible", options.TypeBool, true, "Show the quick help bar at the bottom of the console.", nil},
	} {
		if err := loader.AddOption(ctx, spec.name, spec.typ, spec.def, spec.help, spec.choices...); err != nil {
			return err
		}
	}
	return nil
}
