// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package disableh2c

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func setup(t *testing.T) *addon.Manager {
	t.Helper()
	mgr := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
	t.Cleanup(mgr.Close)
	if err := mgr.Add(t.Context(), New()); err != nil {
		t.Fatal(err)
	}
	return mgr
}

// TestUpgrade ports TestDisableH2CleartextUpgrade.test_upgrade.
func TestUpgrade(t *testing.T) {
	tests := map[string]struct {
		upgrade              string
		connection, settings bool
		remove               bool
	}{
		"success: upgrade":                  {"h2c", true, true, true},
		"success: absent ancillary headers": {"h2c", false, false, true},
		"skip: uppercase value":             {"H2C", true, true, false},
		"skip: list":                        {"h2c, websocket", true, true, false},
		"skip: other upgrade":               {"websocket", true, true, false},
		"skip: no upgrade":                  {"", true, true, false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr := setup(t)
			f := testflow.TFlow()
			f.Request.Headers.Set("keep", "unchanged")
			if test.upgrade != "" {
				f.Request.Headers.Set("UpGrAdE", test.upgrade)
			}
			if test.connection {
				f.Request.Headers.Set("Connection", "foo")
			}
			if test.settings {
				f.Request.Headers.Set("HTTP2-Settings", "bar")
			}
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if test.remove {
				for _, header := range []string{"upgrade", "connection", "http2-settings"} {
					if f.Request.Headers.Has(header) {
						t.Fatalf("%s retained", header)
					}
				}
			} else {
				if diff := gocmp.Diff(test.upgrade, f.Request.Headers.Get("upgrade")); diff != "" {
					t.Fatal(diff)
				}
				if f.Request.Headers.Has("connection") != test.connection || f.Request.Headers.Has("http2-settings") != test.settings {
					t.Fatal("non-h2c headers changed")
				}
			}
			if diff := gocmp.Diff("unchanged", f.Request.Headers.Get("keep")); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// TestPriorKnowledge ports test_prior_knowledge and test_non_killable_flows.
func TestPriorKnowledge(t *testing.T) {
	tests := map[string]struct {
		method, path, version    string
		live, killed, wantKilled bool
	}{
		"success: prior knowledge":    {"PRI", "*", "HTTP/2.0", true, false, true},
		"success: uppercase accessor": {"pri", "*", "HTTP/2.0", true, false, true},
		"skip: already killed":        {"PRI", "*", "HTTP/2.0", true, true, true},
		"skip: archived":              {"PRI", "*", "HTTP/2.0", false, false, false},
		"skip: wrong method":          {"GET", "*", "HTTP/2.0", true, false, false},
		"skip: wrong path":            {"PRI", "/", "HTTP/2.0", true, false, false},
		"skip: wrong version":         {"PRI", "*", "HTTP/1.1", true, false, false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr := setup(t)
			f := testflow.TFlow()
			f.Live = test.live
			f.Request.Method = test.method
			f.Request.Path = test.path
			f.Request.HTTPVersion = test.version
			if test.killed {
				if err := f.Kill(); err != nil {
					t.Fatal(err)
				}
			}
			f.Intercept()
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			got := f.Error != nil && f.Error.Msg == flow.KilledMessage
			if got != test.wantKilled {
				t.Fatalf("killed=%v, want %v", got, test.wantKilled)
			}
			if got && f.Killable() {
				t.Fatal("flow remains killable")
			}
			if test.wantKilled && !test.killed && f.Intercepted() {
				t.Fatal("kill failed to clear interception")
			}
		})
	}
}

func TestWarningTexts(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	mgr := setup(t)
	f := testflow.TFlow()
	f.Request.Headers.Set("Upgrade", "h2c")
	f.Request.Method = "PRI"
	f.Request.Path = "*"
	f.Request.HTTPVersion = "HTTP/2.0"
	if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"HTTP/2 cleartext connections (h2c upgrade requests) are currently not supported.", "Initiating HTTP/2 connections with prior knowledge are currently not supported."} {
		if !strings.Contains(logs.String(), text) {
			t.Fatal(logs.String())
		}
	}
}

func TestOptionsAndCommands(t *testing.T) {
	opts := options.New()
	cmds := command.NewManager()
	mgr := addon.NewManager(opts, cmds, addon.Config{})
	t.Cleanup(mgr.Close)
	before := opts.Keys()
	s := New()
	if err := mgr.Add(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(before, opts.Keys()); diff != "" {
		t.Fatal("upstream declares no options", diff)
	}
	for name := range cmds.Commands() {
		t.Errorf("unexpected command %s; upstream declares none", name)
	}
	if s.Name() != "disableh2c" {
		t.Fatal(s.Name())
	}
}
