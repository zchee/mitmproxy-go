// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"context"
	json "encoding/json/v2"
	"maps"
	"net/url"
	"slices"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/options"
)

func TestWebOptions(t *testing.T) {
	tests := map[string]struct {
		typ     options.Type
		def     any
		choices []string
	}{
		"web_columns":       {typ: options.TypeSeq, def: []string{"tls", "icon", "path", "method", "status", "size", "time"}},
		"web_debug":         {typ: options.TypeBool, def: false},
		"web_host":          {typ: options.TypeStr, def: "127.0.0.1"},
		"web_open_browser":  {typ: options.TypeBool, def: true},
		"web_password":      {typ: options.TypeStr, def: ""},
		"web_port":          {typ: options.TypeInt, def: 8081},
		"web_static_viewer": {typ: options.TypeOptStr, def: new("")},
		"web_theme":         {typ: options.TypeStr, def: "system", choices: []string{"system", "dark", "light"}},
	}
	registered := newWebMaster(t)
	var names []string
	for _, name := range registered.Options.Keys() {
		if strings.HasPrefix(name, "web_") {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	if diff := gocmp.Diff(slices.Sorted(maps.Keys(tests)), names); diff != "" {
		t.Fatalf("active web options (-want +got):\n%s", diff)
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := newWebMaster(t)
			option, ok := m.Options.Lookup(name)
			if !ok {
				t.Fatalf("missing option %s", name)
			}
			if option.Type() != tt.typ {
				t.Fatalf("type=%s want=%s", option.Type(), tt.typ)
			}
			if diff := gocmp.Diff(tt.def, option.Default()); diff != "" {
				t.Fatalf("default (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(tt.choices, option.Choices()); diff != "" {
				t.Fatalf("choices (-want +got):\n%s", diff)
			}
			var expectedHelp string
			for line := range strings.SplitSeq(string(testutil.Fixture(t, "options-upstream.txt")), "\n") {
				fields := strings.SplitN(line, "\t", 4)
				if len(fields) == 4 && fields[0] == name {
					expectedHelp = fields[3]
					var expected, actual any
					if err := json.Unmarshal([]byte(fields[2]), &expected); err != nil {
						t.Fatal(err)
					}
					encoded, err := json.Marshal(option.Default())
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(encoded, &actual); err != nil {
						t.Fatal(err)
					}
					if diff := gocmp.Diff(expected, actual); diff != "" {
						t.Fatalf("fixture default (-want +got):\n%s", diff)
					}
				}
			}
			if expectedHelp == "" || option.Help() != expectedHelp {
				t.Fatalf("help=%q want=%q", option.Help(), expectedHelp)
			}
		})
	}
	t.Run("url", testWebURL)
}

func TestWebColumns(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]struct{}{"test_web_columns": {}}
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				want := []string{"icon", "index", "method", "version", "path", "quickactions", "size", "status", "time", "timestamp", "tls", "comment"}
				got := AvailableColumns()
				if diff := gocmp.Diff(want, got); diff != "" {
					t.Fatalf("columns (-want +got):\n%s", diff)
				}
				got[0] = "changed"
				if AvailableColumns()[0] != want[0] {
					t.Fatal("column vocabulary aliases the caller")
				}
				m := newWebMaster(t)
				if err := m.Do(t.Context(), func(ctx context.Context) error {
					return m.Options.Update(ctx, map[string]any{"web_columns": []string{"future-column"}})
				}); err != nil {
					t.Fatalf("upstream accepts arbitrary column names: %v", err)
				}
			})
		}
	})
}

func testWebURL(t *testing.T) {
	tests := map[string]struct {
		host, password string
		token          bool
	}{
		"ipv4_token":      {host: "127.0.0.1", token: true},
		"ipv6_token":      {host: "::1", token: true},
		"password_hidden": {host: "localhost", password: "fixture-password"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := newWebMaster(t)
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				return m.Options.Update(ctx, map[string]any{"web_host": tt.host, "web_password": tt.password, "web_port": 8081})
			}); err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(m.WebURL())
			if err != nil {
				t.Fatal(err)
			}
			if u.Hostname() != tt.host || u.Port() != "8081" || (u.Query().Get("token") != "") != tt.token {
				t.Fatalf("unexpected URL shape: host=%q port=%q token-present=%t", u.Hostname(), u.Port(), u.Query().Get("token") != "")
			}
			if tt.password != "" && strings.Contains(m.WebURL(), tt.password) {
				t.Fatal("password present in URL")
			}
			if !slices.Equal(m.Options.Seq("web_columns"), []string{"tls", "icon", "path", "method", "status", "size", "time"}) {
				t.Fatal("URL configuration changed columns")
			}
		})
	}
}
