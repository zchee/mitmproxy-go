// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package testutil_test

import (
	json "encoding/json/v2"
	"maps"
	"slices"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// optionRow is one line of an option list in testdata: name, type, default and
// the first line of the help text, separated by tabs.
type optionRow struct {
	Name    string
	Type    string
	Default string
	Help    string
}

// defaultTargets maps each type name, as upstream's typespec_to_str renders it,
// to a constructor for a value that the JSON-encoded default must decode into.
var defaultTargets = map[string]func() any{
	"bool":            func() any { return new(bool) },
	"int":             func() any { return new(int64) },
	"str":             func() any { return new(string) },
	"optional int":    func() any { return new(*int64) },
	"optional str":    func() any { return new(*string) },
	"sequence of str": func() any { return new([]string) },
}

// parseOptionList parses an option list and checks the shape of every row:
// four fields, a known type, a default that decodes as that type, a non-empty
// help line, and names that are unique and sorted.
func parseOptionList(t *testing.T, rel string) []optionRow {
	t.Helper()

	var rows []optionRow
	for n, line := range strings.Split(strings.TrimSuffix(string(testutil.Fixture(t, rel)), "\n"), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Errorf("%s:%d: %d tab-separated fields, want 4: %q", rel, n+1, len(fields), line)
			continue
		}
		row := optionRow{Name: fields[0], Type: fields[1], Default: fields[2], Help: fields[3]}

		target, ok := defaultTargets[row.Type]
		if !ok {
			t.Errorf("%s:%d: option %s has unknown type %q", rel, n+1, row.Name, row.Type)
		} else if err := json.Unmarshal([]byte(row.Default), target()); err != nil {
			t.Errorf("%s:%d: option %s default %s does not decode as %s: %v", rel, n+1, row.Name, row.Default, row.Type, err)
		}
		if row.Help == "" {
			t.Errorf("%s:%d: option %s has no help text", rel, n+1, row.Name)
		}
		rows = append(rows, row)
	}

	names := make([]string, len(rows))
	for i, r := range rows {
		names[i] = r.Name
	}
	if !slices.IsSorted(names) {
		t.Errorf("%s: option names are not sorted", rel)
	}
	if compacted := slices.Compact(slices.Clone(names)); len(compacted) != len(names) {
		t.Errorf("%s: %d rows but only %d distinct names", rel, len(names), len(compacted))
	}
	return rows
}

func TestOptionLists(t *testing.T) {
	upstream := parseOptionList(t, "options-upstream.txt")
	goOnly := parseOptionList(t, "options-go-only.txt")

	byName := func(rows []optionRow) map[string]optionRow {
		m := make(map[string]optionRow, len(rows))
		for _, r := range rows {
			m[r.Name] = r
		}
		return m
	}
	upstreamByName := byName(upstream)

	t.Run("upstream has 117 distinct names", func(t *testing.T) {
		if got, want := len(upstreamByName), 117; got != want {
			t.Errorf("options-upstream.txt has %d distinct names, want %d", got, want)
		}
	})

	t.Run("go-only names", func(t *testing.T) {
		want := []string{"local_redirector_path", "otel_exporter_endpoint", "pprof_addr", "script_max_steps"}
		got := slices.Sorted(maps.Keys(byName(goOnly)))
		if diff := gocmp.Diff(want, got); diff != "" {
			t.Errorf("options-go-only.txt names mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("lists are disjoint", func(t *testing.T) {
		for _, r := range goOnly {
			if _, dup := upstreamByName[r.Name]; dup {
				t.Errorf("option %s is in both options-upstream.txt and options-go-only.txt", r.Name)
			}
		}
	})

	// A few rows checked against upstream's source text, so a regenerated list
	// that renders type or default differently is caught here.
	tests := map[string]struct {
		want optionRow
	}{
		"core str option (mitmproxy/options.py)": {
			want: optionRow{Name: "confdir", Type: "str", Default: `"~/.mitmproxy"`, Help: "Location of the default mitmproxy configuration files."},
		},
		"core sequence option (mitmproxy/options.py)": {
			want: optionRow{Name: "mode", Type: "sequence of str", Default: `["regular"]`},
		},
		"optional int option (mitmproxy/options.py)": {
			want: optionRow{Name: "listen_port", Type: "optional int", Default: "null"},
		},
		"bool option (mitmproxy/options.py)": {
			want: optionRow{Name: "ssl_insecure", Type: "bool", Default: "false"},
		},
		"int option (mitmproxy/tools/web/webaddons.py)": {
			want: optionRow{Name: "web_port", Type: "int", Default: "8081", Help: "Web UI port."},
		},
		"addon option (mitmproxy/addons/tlsconfig.py)": {
			want: optionRow{Name: "tls_version_client_min", Type: "str", Default: `"TLS1_2"`},
		},
		"option added only by the terminal log (mitmproxy/addons/termlog.py)": {
			want: optionRow{Name: "termlog_verbosity", Type: "str", Default: `"info"`, Help: "Log verbosity."},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := upstreamByName[tt.want.Name]
			if !ok {
				t.Fatalf("option %s is missing from options-upstream.txt", tt.want.Name)
			}
			if tt.want.Help == "" {
				got.Help = "" // only the type and default are pinned for long help texts
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("option %s mismatch (-want +got):\n%s", tt.want.Name, diff)
			}
		})
	}
}
