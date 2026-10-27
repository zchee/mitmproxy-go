// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package testutil_test

import (
	"context"
	json "encoding/json/v2"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/tools/console"
	"github.com/zchee/mitmproxy-go/internal/tools/dump"
	"github.com/zchee/mitmproxy-go/internal/tools/web"
	"github.com/zchee/mitmproxy-go/options"
)

func TestFinalOptionRegistry(t *testing.T) {
	upstream := parseOptionList(t, "options-upstream.txt")
	goOnly := parseOptionList(t, "options-go-only.txt")
	registries := assembledOptionRegistries(t)
	omitted := map[string][]string{
		"dump":    strings.Fields(`console_default_contentview console_eventlog_verbosity console_flowlist_layout console_focus_follow console_layout console_layout_headers console_mouse console_palette console_palette_transparent console_quickhelp_visible console_strip_trailing_newlines web_columns web_debug web_host web_open_browser web_password web_port web_static_viewer web_theme intercept intercept_active view_filter view_order view_order_reversed`),
		"web":     strings.Fields(`console_default_contentview console_eventlog_verbosity console_flowlist_layout console_layout console_layout_headers console_mouse console_palette console_palette_transparent console_quickhelp_visible console_strip_trailing_newlines dumper_default_contentview dumper_filter flow_detail keepserving`),
		"console": strings.Fields(`web_columns web_debug web_host web_open_browser web_password web_port web_static_viewer web_theme dumper_default_contentview dumper_filter flow_detail keepserving termlog_verbosity`),
	}
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct{ tool, check string }{
			"dump_names":       {tool: "dump", check: "names"},
			"web_names":        {tool: "web", check: "names"},
			"console_names":    {tool: "console", check: "names"},
			"dump_metadata":    {tool: "dump", check: "metadata"},
			"web_metadata":     {tool: "web", check: "metadata"},
			"console_metadata": {tool: "console", check: "metadata"},
			"union_123":        {check: "union"},
			"disjoint_lists":   {check: "disjoint"},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				if tt.check == "union" {
					want, got := make(map[string]struct{}), make(map[string]struct{})
					for _, row := range upstream {
						want[row.Name] = struct{}{}
					}
					for _, row := range goOnly {
						want[row.Name] = struct{}{}
					}
					for _, registry := range registries {
						for _, option := range registry.Items() {
							got[option.Name()] = struct{}{}
						}
					}
					if len(want) != 123 || len(got) != 123 {
						t.Fatalf("combined option count: fixture=%d, registered=%d, want 123", len(want), len(got))
					}
					if diff := gocmp.Diff(slices.Sorted(maps.Keys(want)), slices.Sorted(maps.Keys(got))); diff != "" {
						t.Fatalf("combined option identities (-want +got):\n%s", diff)
					}
					return
				}
				if tt.check == "disjoint" {
					upstreamNames := make(map[string]struct{}, len(upstream))
					for _, row := range upstream {
						upstreamNames[row.Name] = struct{}{}
					}
					for _, row := range goOnly {
						if _, exists := upstreamNames[row.Name]; exists {
							t.Errorf("option %s occurs in both lists", row.Name)
						}
					}
					return
				}
				want := make(map[string]optionRow)
				for _, row := range upstream {
					if !slices.Contains(omitted[tt.tool], row.Name) {
						want[row.Name] = row
					}
				}
				for _, row := range goOnly {
					want[row.Name] = row
				}
				counts := map[string]int{"dump": 99, "web": 109, "console": 110}
				if len(want) != counts[tt.tool] {
					t.Fatalf("%s fixture/complement count=%d, want %d", tt.tool, len(want), counts[tt.tool])
				}
				got := make(map[string]options.Option)
				for _, option := range registries[tt.tool].Items() {
					got[option.Name()] = option
				}
				if diff := gocmp.Diff(slices.Sorted(maps.Keys(want)), slices.Sorted(maps.Keys(got))); diff != "" {
					t.Fatalf("%s registered names (-want +got):\n%s", tt.tool, diff)
				}
				if tt.check == "metadata" {
					for name, row := range want {
						option := got[name]
						if actual := option.Type().String(); actual != row.Type {
							t.Errorf("%s type=%s, want %s", name, actual, row.Type)
						}
						var expected, actual any
						if err := json.Unmarshal([]byte(row.Default), &expected); err != nil {
							t.Fatal(err)
						}
						raw, err := json.Marshal(option.Default())
						if err != nil {
							t.Fatal(err)
						}
						if err := json.Unmarshal(raw, &actual); err != nil {
							t.Fatal(err)
						}
						if diff := gocmp.Diff(expected, actual); diff != "" {
							t.Errorf("%s default (-want +got):\n%s", name, diff)
						}
						if slices.ContainsFunc(goOnly, func(row optionRow) bool { return row.Name == name }) && option.Help() != row.Help {
							t.Errorf("%s Go-only help=%q, want %q", name, option.Help(), row.Help)
						}
					}
				}
			})
		}
	})
}

func assembledOptionRegistries(t *testing.T) map[string]*options.Manager {
	t.Helper()
	dm, err := dump.New(t.Context(), dump.Config{WithTermlog: true, WithDumper: true, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := dm.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	wm, err := web.New(t.Context(), web.Config{WithTermlog: true, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := wm.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	cm, err := console.New(t.Context(), console.Config{Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cm.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	return map[string]*options.Manager{"dump": dm.Options, "web": wm.Options, "console": cm.Options}
}
