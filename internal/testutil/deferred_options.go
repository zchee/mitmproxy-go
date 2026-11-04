// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package testutil

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// UpstreamOptionInput distinguishes live upstream registries from the projected manifest.
type UpstreamOptionInput uint8

const (
	// RawLiveOptions requires the pin's deferred names before projection.
	RawLiveOptions UpstreamOptionInput = iota
	// ProjectedOptions requires all 117 supported upstream names and no deferred names.
	ProjectedOptions
)

// DeferredOption contains the metadata checked before an upstream option is excluded.
type DeferredOption struct {
	Type    string `json:"type"`
	Default any    `json:"default"`
}

// DeferredOptionPolicy bounds test-only projections to the two deferred upstream options.
// It never changes the runtime registry or the metadata of surviving options.
type DeferredOptionPolicy struct {
	names []string
	known map[string]bool
}

// DeferredUpstreamOptions reads the shared policy and the disjoint option manifests.
// It fails the test if the frozen two-name policy or either manifest is invalid.
func DeferredUpstreamOptions(tb testing.TB) DeferredOptionPolicy {
	tb.Helper()
	readNames := func(file string) []string {
		var names []string
		for line := range strings.Lines(string(Fixture(tb, file))) {
			fields := strings.Split(strings.TrimSuffix(line, "\n"), "\t")
			if len(fields) != 4 {
				tb.Fatalf("%s: malformed option row %q", file, line)
			}
			names = append(names, fields[0])
		}
		return names
	}
	policy, err := NewDeferredOptionPolicy(Fixture(tb, "deferred-upstream-options.txt"), readNames("options-upstream.txt"), readNames("options-go-only.txt"))
	if err != nil {
		tb.Fatal(err)
	}
	return policy
}

// NewDeferredOptionPolicy validates the policy contents and projected/Go-only names.
// It rejects unsorted, duplicate, missing or additional deferred names, a projected
// inventory other than 117 distinct names, and any overlap with Go-only names.
func NewDeferredOptionPolicy(data []byte, projected, goOnly []string) (DeferredOptionPolicy, error) {
	names := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if !strings.HasSuffix(string(data), "\n") || !slices.Equal(names, []string{"emudhra", "emudhra_old"}) {
		return DeferredOptionPolicy{}, fmt.Errorf("deferred upstream options must be exactly emudhra and emudhra_old, sorted and newline-terminated: %q", data)
	}
	known := make(map[string]bool, len(projected))
	for _, name := range projected {
		if name == "" || known[name] || slices.Contains(names, name) {
			return DeferredOptionPolicy{}, fmt.Errorf("invalid projected option name %q", name)
		}
		known[name] = true
	}
	if len(known) != 117 {
		return DeferredOptionPolicy{}, fmt.Errorf("projected option inventory has %d names, want 117", len(known))
	}
	for _, name := range goOnly {
		if known[name] || slices.Contains(names, name) {
			return DeferredOptionPolicy{}, fmt.Errorf("option %q in the Go-only manifest overlaps upstream options", name)
		}
	}
	return DeferredOptionPolicy{names: names, known: known}, nil
}

// Names returns a copy of the exact deferred option names.
func (p DeferredOptionPolicy) Names() []string { return slices.Clone(p.names) }

// FlagNames returns only the positive and negative spellings of the deferred options.
func (p DeferredOptionPolicy) FlagNames() []string {
	var flags []string
	for _, name := range p.names {
		name = strings.ReplaceAll(name, "_", "-")
		flags = append(flags, "--"+name, "--no-"+name)
	}
	return flags
}

// CheckGoNames rejects registration of either deferred option on the Go side.
func (p DeferredOptionPolicy) CheckGoNames(names []string) error {
	for _, name := range names {
		if slices.Contains(p.names, name) {
			return fmt.Errorf("deferred upstream option %q is registered in Go", name)
		}
	}
	return nil
}

// Project validates the exact pin and master inventory, then removes only the deferred names.
// master is DumpMaster, WebMaster or union. ProjectedOptions is valid only for the
// union manifest. Missing known names, unexpected extras and partial deferred
// presence fail before any rows are removed; the input map remains unchanged.
func (p DeferredOptionPolicy) Project(kind UpstreamOptionInput, pin, master string, rows map[string]DeferredOption) (map[string]DeferredOption, error) {
	var newPin bool
	switch pin {
	case "3368a0a06ae6195aad817a1ece1aaeb6fe0353a1":
	case "51c1d6b2d8d3367a773411eb7a3eeccec82b3ea7":
		newPin = true
	default:
		return nil, fmt.Errorf("unknown upstream option pin %q", pin)
	}
	var omitted []string
	switch master {
	case "DumpMaster":
		omitted = strings.Fields("console_default_contentview console_eventlog_verbosity console_flowlist_layout console_focus_follow console_layout console_layout_headers console_mouse console_palette console_palette_transparent console_quickhelp_visible console_strip_trailing_newlines web_columns web_debug web_host web_open_browser web_password web_port web_static_viewer web_theme intercept intercept_active view_filter view_order view_order_reversed")
	case "WebMaster":
		omitted = strings.Fields("console_default_contentview console_eventlog_verbosity console_flowlist_layout console_layout console_layout_headers console_mouse console_palette console_palette_transparent console_quickhelp_visible console_strip_trailing_newlines dumper_default_contentview dumper_filter flow_detail keepserving")
	case "union":
	default:
		return nil, fmt.Errorf("unknown upstream option master %q", master)
	}
	if kind != RawLiveOptions && kind != ProjectedOptions || kind == ProjectedOptions && master != "union" {
		return nil, fmt.Errorf("invalid upstream option input kind %d for %s", kind, master)
	}
	expected := maps.Clone(p.known)
	for _, name := range omitted {
		delete(expected, name)
	}
	for _, name := range p.names {
		row, present := rows[name]
		wantPresent := kind == RawLiveOptions && newPin
		if present != wantPresent {
			return nil, fmt.Errorf("upstream option %q presence=%v, want %v at %s", name, present, wantPresent, pin)
		}
		if present {
			value, ok := row.Default.(bool)
			if row.Type != "bool" || !ok || value {
				return nil, fmt.Errorf("deferred option %q must have type bool and default false: %+v", name, row)
			}
			expected[name] = true
		}
	}
	if !slices.Equal(slices.Sorted(maps.Keys(expected)), slices.Sorted(maps.Keys(rows))) {
		return nil, fmt.Errorf("%s upstream option names differ: expected %v, got %v", master, slices.Sorted(maps.Keys(expected)), slices.Sorted(maps.Keys(rows)))
	}
	projected := maps.Clone(rows)
	for _, name := range p.names {
		delete(projected, name)
	}
	return projected, nil
}
