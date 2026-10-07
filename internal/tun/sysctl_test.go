// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tun

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestReversePathFilter(t *testing.T) {
	// The expected end states are from src/packet_sources/tun.rs in mitmproxy-rs.
	tests := map[string]struct {
		before map[string]string
		after  map[string]string
	}{
		"success: strict global preserves peers":          {before: map[string]string{"all": "1\n", "default": "0\n", "eth0": "0\n", "eth1": "2\n", "tun0": "2\n"}, after: map[string]string{"all": "0", "default": "1", "eth0": "1", "eth1": "2\n", "tun0": "0"}},
		"success: loose global raises peers":              {before: map[string]string{"all": "2\n", "default": "1\n", "eth0": "0\n", "tun0": "1\n"}, after: map[string]string{"all": "0", "default": "2", "eth0": "2", "tun0": "0"}},
		"success: disabled global leaves peers untouched": {before: map[string]string{"all": "0\n", "default": "1\n", "eth0": "2\n", "tun0": "1\n"}, after: map[string]string{"all": "0\n", "default": "1\n", "eth0": "2\n", "tun0": "0"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for iface, value := range tt.before {
				writeSysctl(t, root, iface, "rp_filter", value)
			}
			if err := disableRPFilter(root, "tun0", slog.Default()); err != nil {
				t.Fatal(err)
			}
			actual := make(map[string]string)
			for iface := range tt.before {
				data, err := os.ReadFile(filepath.Join(root, iface, "rp_filter"))
				if err != nil {
					t.Fatal(err)
				}
				actual[iface] = string(data)
			}
			if diff := cmp.Diff(tt.after, actual); diff != "" {
				t.Fatalf("reverse path filter end state (-want +got):\n%s", diff)
			}
		})
	}
}

func TestConfigureDevice(t *testing.T) {
	// rs:src/packet_sources/tun.rs:89-107 specifies independent writes and error logs.
	tests := map[string]struct {
		missingFilter bool
		missingAll    bool
		wantLog       string
	}{
		"success: all sysctls": {},
		"error: filter failure does not suppress other settings":        {missingFilter: true, wantLog: "failed to set rp_filter:"},
		"error: global filter failure does not suppress other settings": {missingAll: true, wantLog: "failed to set rp_filter:"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeSysctl(t, root, "tun0", "route_localnet", "0\n")
			writeSysctl(t, root, "tun0", "accept_local", "0\n")
			if !tt.missingFilter {
				writeSysctl(t, root, "tun0", "rp_filter", "1\n")
			} else {
				if err := os.Mkdir(filepath.Join(root, "tun0", "rp_filter"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if !tt.missingAll {
				writeSysctl(t, root, "all", "rp_filter", "1\n")
			}
			var logs bytes.Buffer
			configureDevice(root, "tun0", slog.New(slog.NewTextHandler(&logs, nil)))
			for _, field := range []string{"route_localnet", "accept_local"} {
				data, err := os.ReadFile(filepath.Join(root, "tun0", field))
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != "1" {
					t.Errorf("%s = %q, want 1", field, data)
				}
			}
			if tt.wantLog != "" && !strings.Contains(logs.String(), tt.wantLog) {
				t.Errorf("logs %q do not contain %q", logs.String(), tt.wantLog)
			}
		})
	}
}

func TestConfigureDeviceLogsBothLocalSettingsFailures(t *testing.T) {
	// rs:src/packet_sources/tun.rs:89-107 specifies the three exact diagnostics.
	var logs bytes.Buffer
	configureDevice(t.TempDir(), "tun0", slog.New(slog.NewTextHandler(&logs, nil)))
	for _, text := range []string{"failed to set rp_filter:", "Failed to enable route_localnet:", "Failed to enable accept_local:"} {
		if !strings.Contains(logs.String(), text) {
			t.Errorf("missing diagnostic %q: %s", text, logs.String())
		}
	}
}

func TestReversePathFilterPreservesGlobalOnPeerFailure(t *testing.T) {
	root := t.TempDir()
	writeSysctl(t, root, "tun0", "rp_filter", "1\n")
	writeSysctl(t, root, "all", "rp_filter", "2\n")
	if err := os.MkdirAll(filepath.Join(root, "eth0", "rp_filter"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := disableRPFilter(root, "tun0", slog.Default()); err == nil {
		t.Fatal("expected peer update failure")
	}
	global, err := os.ReadFile(filepath.Join(root, "all", "rp_filter"))
	if err != nil {
		t.Fatal(err)
	}
	if string(global) != "2\n" {
		t.Errorf("global filter lowered before updating all peers: %q", global)
	}
}

func writeSysctl(t *testing.T, root, iface, field, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, iface), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, iface, field), []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}
