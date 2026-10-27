// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package acceptance_test

import (
	"context"
	json "encoding/json/v2"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/internal/tools/web"
)

func adaptWebFixtureMetadata(t *testing.T, values map[string]any, goRuntime bool) {
	t.Helper()
	options, ok := values["/options"].(map[string]any)
	if !ok {
		t.Fatal("options must be a JSON object")
	}
	commands, ok := values["/commands"].(map[string]any)
	if !ok {
		t.Fatal("commands must be a JSON object")
	}
	if goRuntime {
		names := goOnlyMetadataNames(t)
		for _, name := range names {
			if _, exists := options[name]; !exists {
				t.Fatalf("assembled Go option registry is missing %s", name)
			}
		}
		for _, name := range names {
			delete(options, name)
		}
		return
	}
	browser, ok := commands["browser.start"].(map[string]any)
	if !ok {
		t.Fatal("pinned Python registry is missing browser.start")
	}
	wantParameters := []any{map[string]any{"name": "browser", "type": "str", "kind": "POSITIONAL_OR_KEYWORD"}}
	if !gocmp.Equal(browser["parameters"], wantParameters) || browser["signature_help"] != "browser.start browser" {
		t.Fatal("browser.start metadata no longer matches the named compatibility adapter")
	}
	browser["parameters"] = []any{map[string]any{"name": "arg0", "type": "str", "kind": "VAR_POSITIONAL"}}
	browser["signature_help"] = "browser.start *arg0"
	export, ok := commands["export"].(map[string]any)
	if !ok || export["return_type"] != "str" || export["signature_help"] != "export format f -> str" {
		t.Fatal("export metadata no longer matches the named byte-result adapter")
	}
	export["return_type"] = "bytes"
	export["signature_help"] = "export format f -> bytes"
}

func goOnlyMetadataNames(t *testing.T) []string {
	t.Helper()
	var names []string
	for line := range strings.Lines(string(testutil.Fixture(t, "options-go-only.txt"))) {
		name, _, exists := strings.Cut(line, "\t")
		if !exists {
			t.Fatal("Go-only option fixture has an invalid row")
		}
		names = append(names, name)
	}
	slices.Sort(names)
	want := []string{"content_decode_limit", "local_redirector_path", "max_client_connections", "otel_exporter_endpoint", "pprof_addr", "script_max_steps"}
	if diff := gocmp.Diff(want, names); diff != "" {
		t.Fatalf("Go-only option identities (-want +got):\n%s", diff)
	}
	return names
}

func TestGoOnlyMetadataAdapter(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct {
			run func(*testing.T, map[string]any, map[string]any)
		}{
			"six_present": {run: func(t *testing.T, _, _ map[string]any) {
				m, err := web.New(t.Context(), web.Config{Stdout: io.Discard, Stderr: io.Discard})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
						t.Error(err)
					}
				})
				for _, name := range goOnlyMetadataNames(t) {
					if !m.Options.Has(name) {
						t.Fatalf("assembled web registry is missing Go-only metadata %s", name)
					}
				}
			}},
			"six_removed": {run: func(t *testing.T, options, _ map[string]any) {
				before := len(options)
				adaptWebFixtureMetadata(t, map[string]any{"/options": options, "/commands": map[string]any{}}, true)
				if got := before - len(options); got != 6 {
					t.Fatalf("removed %d options, want exactly six", got)
				}
				for _, name := range goOnlyMetadataNames(t) {
					if _, ok := options[name]; ok {
						t.Errorf("Go-only metadata survived: %s", name)
					}
				}
			}},
			"upstream_preserved": {run: func(t *testing.T, options, upstream map[string]any) {
				commands := map[string]any{"untouched.command": map[string]any{"return_type": "str"}}
				before := maps.Clone(commands)
				adaptWebFixtureMetadata(t, map[string]any{"/options": options, "/commands": commands}, true)
				if diff := gocmp.Diff(upstream, options); diff != "" {
					t.Fatalf("upstream metadata changed (-want +got):\n%s", diff)
				}
				if diff := gocmp.Diff(before, commands); diff != "" {
					t.Fatalf("command metadata changed (-want +got):\n%s", diff)
				}
			}},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				upstream := fixtureMetadata(t, "options-upstream.txt")
				options := maps.Clone(upstream)
				maps.Copy(options, fixtureMetadata(t, "options-go-only.txt"))
				tt.run(t, options, upstream)
			})
		}
	})
}

func fixtureMetadata(t *testing.T, fixture string) map[string]any {
	t.Helper()
	metadata := make(map[string]any)
	for line := range strings.Lines(string(testutil.Fixture(t, fixture))) {
		fields := strings.SplitN(line, "\t", 4)
		if len(fields) != 4 {
			t.Fatalf("invalid option metadata row in %s", fixture)
		}
		var value any
		if err := json.Unmarshal([]byte(fields[2]), &value); err != nil {
			t.Fatal(err)
		}
		metadata[fields[0]] = map[string]any{"type": fields[1], "default": value, "help": fields[3]}
	}
	return metadata
}
