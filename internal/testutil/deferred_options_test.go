// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package testutil_test

import (
	"maps"
	"slices"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

const (
	oldOptionPin = "3368a0a06ae6195aad817a1ece1aaeb6fe0353a1"
	newOptionPin = "51c1d6b2d8d3367a773411eb7a3eeccec82b3ea7"
)

func deferredOptionRows(t *testing.T) map[string]testutil.DeferredOption {
	t.Helper()
	rows := make(map[string]testutil.DeferredOption)
	for _, row := range parseOptionList(t, "options-upstream.txt") {
		rows[row.Name] = testutil.DeferredOption{Type: row.Type, Default: row.Default}
	}
	return rows
}

func TestDeferredUpstreamOptions(t *testing.T) {
	policy := testutil.DeferredUpstreamOptions(t)
	rows := deferredOptionRows(t)
	newPolicy := func(data string, goOnly []string) error {
		_, err := testutil.NewDeferredOptionPolicy([]byte(data), slices.Sorted(maps.Keys(rows)), goOnly)
		return err
	}
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"exact_two": {func(t *testing.T) {
				if diff := gocmp.Diff([]string{"emudhra", "emudhra_old"}, policy.Names()); diff != "" {
					t.Fatal(diff)
				}
				for _, data := range []string{"emudhra_old\nemudhra\n", "emudhra\nemudhra_old", "emudhra*\nemudhra_old\n", "# comment\nemudhra\nemudhra_old\n"} {
					if err := newPolicy(data, nil); err == nil {
						t.Errorf("accepted malformed policy %q", data)
					}
				}
			}},
			"duplicate_rejected": {func(t *testing.T) {
				if err := newPolicy("emudhra\nemudhra\n", nil); err == nil {
					t.Fatal("accepted duplicate deferred name")
				}
			}},
			"third_name_rejected": {func(t *testing.T) {
				if err := newPolicy("emudhra\nemudhra_old\nextra\n", nil); err == nil {
					t.Fatal("accepted a third deferred name")
				}
			}},
			"missing_name_rejected": {func(t *testing.T) {
				if err := newPolicy("emudhra\n", nil); err == nil {
					t.Fatal("accepted missing deferred name")
				}
			}},
			"old_pin_absent": {func(t *testing.T) {
				got, err := policy.Project(testutil.RawLiveOptions, oldOptionPin, "union", rows)
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(rows, got); diff != "" {
					t.Fatal(diff)
				}
				for _, kind := range []testutil.UpstreamOptionInput{testutil.RawLiveOptions, testutil.ProjectedOptions} {
					if _, err := policy.Project(kind, "unknown", "union", rows); err == nil {
						t.Fatal("accepted unknown pin")
					}
				}
			}},
			"new_pin_both_present": {func(t *testing.T) {
				raw := maps.Clone(rows)
				for _, name := range policy.Names() {
					raw[name] = testutil.DeferredOption{Type: "bool", Default: false}
				}
				got, err := policy.Project(testutil.RawLiveOptions, newOptionPin, "union", raw)
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(rows, got); diff != "" {
					t.Fatal(diff)
				}
				if len(raw) != 119 {
					t.Fatal("projection mutated its raw input")
				}
				if _, err := policy.Project(testutil.RawLiveOptions, oldOptionPin, "union", raw); err == nil {
					t.Fatal("accepted deferred names at old pin")
				}
			}},
			"partial_presence_rejected": {func(t *testing.T) {
				for _, name := range policy.Names() {
					raw := maps.Clone(rows)
					raw[name] = testutil.DeferredOption{Type: "bool", Default: false}
					if _, err := policy.Project(testutil.RawLiveOptions, newOptionPin, "union", raw); err == nil {
						t.Errorf("accepted only %s", name)
					}
				}
				for _, shape := range []testutil.DeferredOption{{Type: "str", Default: false}, {Type: "bool", Default: true}, {Type: "bool", Default: "false"}} {
					raw := maps.Clone(rows)
					for _, name := range policy.Names() {
						raw[name] = shape
					}
					if _, err := policy.Project(testutil.RawLiveOptions, newOptionPin, "union", raw); err == nil {
						t.Errorf("accepted malformed deferred shape %+v", shape)
					}
				}
			}},
			"unexpected_upstream_extra": {func(t *testing.T) {
				raw := maps.Clone(rows)
				raw["unexpected"] = testutil.DeferredOption{Type: "bool", Default: false}
				if _, err := policy.Project(testutil.RawLiveOptions, oldOptionPin, "union", raw); err == nil {
					t.Fatal("accepted unlisted upstream option")
				}
				delete(raw, "unexpected")
				delete(raw, "server")
				if _, err := policy.Project(testutil.RawLiveOptions, oldOptionPin, "union", raw); err == nil {
					t.Fatal("accepted lost known upstream option")
				}
			}},
			"go_registration_rejected": {func(t *testing.T) {
				for _, name := range policy.Names() {
					if err := policy.CheckGoNames([]string{"server", name}); err == nil {
						t.Errorf("accepted Go registration of %s", name)
					}
				}
				if err := policy.CheckGoNames([]string{"server", "emudhra_custom"}); err != nil {
					t.Fatal(err)
				}
			}},
			"go_only_disjoint": {func(t *testing.T) {
				var names []string
				for _, row := range parseOptionList(t, "options-go-only.txt") {
					names = append(names, row.Name)
				}
				if err := newPolicy("emudhra\nemudhra_old\n", names); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"emudhra", "emudhra_old", "server"} {
					if err := newPolicy("emudhra\nemudhra_old\n", append(slices.Clone(names), name)); err == nil {
						t.Errorf("accepted Go-only overlap %s", name)
					}
				}
			}},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}

func TestDeferredOptionInventories(t *testing.T) {
	policy := testutil.DeferredUpstreamOptions(t)
	rows := deferredOptionRows(t)
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"flag_spellings": {func(t *testing.T) {
				want := []string{"--emudhra", "--no-emudhra", "--emudhra-old", "--no-emudhra-old"}
				if diff := gocmp.Diff(want, policy.FlagNames()); diff != "" {
					t.Fatal(diff)
				}
				flags := map[string]string{"--server": "server", "--no-server": "server", "--emudhra-custom": "emudhra_custom"}
				for _, flag := range policy.FlagNames() {
					flags[flag] = "deferred"
				}
				for _, flag := range policy.FlagNames() {
					delete(flags, flag)
				}
				if len(flags) != 3 || flags["--emudhra-custom"] != "emudhra_custom" {
					t.Fatal("flag projection removed an unrelated spelling")
				}
			}},
			"addon_defaults": {func(t *testing.T) {
				omitted := strings.Fields("console_default_contentview console_eventlog_verbosity console_flowlist_layout console_focus_follow console_layout console_layout_headers console_mouse console_palette console_palette_transparent console_quickhelp_visible console_strip_trailing_newlines web_columns web_debug web_host web_open_browser web_password web_port web_static_viewer web_theme intercept intercept_active view_filter view_order view_order_reversed")
				checkDeferredMasterProjection(t, policy, rows, "DumpMaster", omitted, 93)
			}},
			"web_metadata": {func(t *testing.T) {
				omitted := strings.Fields("console_default_contentview console_eventlog_verbosity console_flowlist_layout console_layout console_layout_headers console_mouse console_palette console_palette_transparent console_quickhelp_visible console_strip_trailing_newlines dumper_default_contentview dumper_filter flow_detail keepserving")
				checkDeferredMasterProjection(t, policy, rows, "WebMaster", omitted, 103)
			}},
			"generated_bindings": {func(t *testing.T) {
				for _, pin := range []string{oldOptionPin, newOptionPin} {
					got, err := policy.Project(testutil.ProjectedOptions, pin, "union", rows)
					if err != nil {
						t.Fatal(err)
					}
					if len(got) != 117 || !gocmp.Equal(rows, got) {
						t.Fatal("projected manifest changed")
					}
					raw := maps.Clone(rows)
					raw["emudhra"] = testutil.DeferredOption{Type: "bool", Default: false}
					if _, err := policy.Project(testutil.ProjectedOptions, pin, "union", raw); err == nil {
						t.Fatal("accepted deferred name in projected manifest")
					}
				}
			}},
			"third_extra_red": {func(t *testing.T) {
				for _, kind := range []testutil.UpstreamOptionInput{testutil.RawLiveOptions, testutil.ProjectedOptions} {
					raw := maps.Clone(rows)
					raw["emudhra_other"] = testutil.DeferredOption{Type: "bool", Default: false}
					if _, err := policy.Project(kind, oldOptionPin, "union", raw); err == nil {
						t.Fatal("accepted third extra by prefix")
					}
				}
			}},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}

func checkDeferredMasterProjection(t *testing.T, policy testutil.DeferredOptionPolicy, rows map[string]testutil.DeferredOption, master string, omitted []string, count int) {
	t.Helper()
	want := maps.Clone(rows)
	for _, name := range omitted {
		delete(want, name)
	}
	raw := maps.Clone(want)
	for _, name := range policy.Names() {
		raw[name] = testutil.DeferredOption{Type: "bool", Default: false}
	}
	projected, err := policy.Project(testutil.RawLiveOptions, newOptionPin, master, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(projected) != count || !gocmp.Equal(want, projected) {
		t.Fatalf("%s projection changed survivors (-want +got):\n%s", master, gocmp.Diff(want, projected))
	}
	delete(raw, "server")
	if _, err := policy.Project(testutil.RawLiveOptions, newOptionPin, master, raw); err == nil {
		t.Fatalf("%s accepted a lost known name", master)
	}
}
