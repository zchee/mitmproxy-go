// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package view

import (
	"maps"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestOptionTable(t *testing.T) {
	m := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{})
	defer m.Close()
	must(t, m.Add(t.Context(), New(m)))
	tests := map[string]struct {
		typ     options.Type
		def     any
		help    string
		choices []string
	}{
		"view_filter":          {options.TypeOptStr, (*string)(nil), "Limit the view to matching flows.", nil},
		"view_order":           {options.TypeStr, "time", "Flow sort order.", []string{"time", "method", "url", "size"}},
		"view_order_reversed":  {options.TypeBool, false, "Reverse the sorting order.", nil},
		"console_focus_follow": {options.TypeBool, false, "Focus follows new flows.", nil},
	}
	if len(m.Options().Items()) != len(tests) {
		t.Fatal("option count")
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opt, ok := m.Options().Lookup(name)
			if !ok || opt.Type() != tt.typ || opt.Help() != tt.help {
				t.Fatal(opt)
			}
			if diff := cmp.Diff(tt.def, opt.Default()); diff != "" {
				t.Fatal(diff)
			}
			if diff := cmp.Diff(tt.choices, opt.Choices()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestCommandTable(t *testing.T) {
	m := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{})
	defer m.Close()
	v := New(m)
	must(t, m.Add(t.Context(), v))
	tests := map[string]struct{ signature string }{
		"view.focus.go": {"view.focus.go offset"}, "view.focus.next": {"view.focus.next "}, "view.focus.prev": {"view.focus.prev "},
		"view.order.options": {"view.order.options  -> str[]"}, "view.order.reverse": {"view.order.reverse boolean"}, "view.order.set": {"view.order.set order_key"}, "view.order": {"view.order  -> str"},
		"view.filter.set": {"view.filter.set filter_expr"}, "view.clear": {"view.clear "}, "view.clear_unmarked": {"view.clear_unmarked "},
		"view.settings.getval": {"view.settings.getval flow key default -> str"}, "view.settings.setval.toggle": {"view.settings.setval.toggle flows key"}, "view.settings.setval": {"view.settings.setval flows key value"},
		"view.flows.duplicate": {"view.flows.duplicate flows"}, "view.flows.remove": {"view.flows.remove flows"}, "view.flows.resolve": {"view.flows.resolve flow_spec -> flow[]"}, "view.flows.create": {"view.flows.create method url"}, "view.flows.load": {"view.flows.load path"},
		"view.properties.length": {"view.properties.length  -> int"}, "view.properties.marked": {"view.properties.marked  -> bool"}, "view.properties.marked.toggle": {"view.properties.marked.toggle "}, "view.properties.inbounds": {"view.properties.inbounds index -> bool"},
	}
	found := maps.Collect(m.Commands().Commands())
	if len(found) != len(tests) {
		t.Fatal("command count")
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cmd := found[name]
			if cmd == nil || cmd.SignatureHelp() != tt.signature {
				t.Fatalf("%s: %+v", tt.signature, cmd)
			}
		})
	}
	must(t, m.Trigger(t.Context(), addon.RequestHeadersHook{Flow: fixture("GET", 1)}))
	value, err := m.Commands().CallStrings(t.Context(), "view.settings.setval", []string{"@focus", "key", "value"})
	if err != nil || value != nil {
		t.Fatal(value, err)
	}
	value, err = m.Commands().CallStrings(t.Context(), "view.settings.getval", []string{"@focus", "key", "default"})
	if err != nil || value != "value" {
		t.Fatal(value, err)
	}
	value, err = m.Commands().CallStrings(t.Context(), "view.flows.resolve", []string{"@shown"})
	if err != nil || len(value.([]flow.Flow)) != 1 {
		t.Fatal(value, err)
	}
}
