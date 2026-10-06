// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	json "encoding/json/v2"
	"net"
	"os"
	"path/filepath"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestConfigureSuite(t *testing.T) {
	output := filepath.Join(t.TempDir(), "fuzzingclient.json")
	image, err := configureSuite("cases.json", "fuzzingclient.json", "ws://127.0.0.1:12345", output)
	if err != nil {
		t.Fatal(err)
	}
	got, err := loadJSON[suiteConfig](output)
	if err != nil {
		t.Fatal(err)
	}
	if image != suiteImage || got.Image != suiteImage || len(got.Cases) != suiteCases || got.Outdir != "/reports/clients" {
		t.Fatalf("configured suite=%+v image=%q", got, image)
	}
	if diff := gocmp.Diff([]suiteServer{{suiteAgent, "ws://127.0.0.1:12345"}}, got.Servers); diff != "" {
		t.Fatal(diff)
	}
	if len(got.ExcludeCases) != 0 || len(got.ExcludeAgentCases) != 0 {
		t.Fatal("configuration excludes expected cases")
	}
	bad := got
	bad.Image = "different image"
	data, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := configureSuite("cases.json", badPath, "ws://127.0.0.1:12345", filepath.Join(t.TempDir(), "output.json")); err == nil {
		t.Fatal("image mismatch accepted")
	}
}

func TestConfigureSuitePrefixes(t *testing.T) {
	tests := map[string]struct {
		prefixes  []string
		wantCount int
		wantError bool
	}{
		"complete":           {wantCount: suiteCases},
		"base":               {prefixes: []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"}, wantCount: 301},
		"compression family": {prefixes: []string{"12.2"}, wantCount: 18},
		"two families":       {prefixes: []string{"13.1", "13.7"}, wantCount: 36},
		"unknown":            {prefixes: []string{"99"}, wantError: true},
		"empty":              {prefixes: []string{""}, wantError: true},
		"duplicate":          {prefixes: []string{"12.2", "12.2"}, wantError: true},
		"overlapping":        {prefixes: []string{"12", "12.2"}, wantError: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "fuzzingclient.json")
			_, err := configureSuite("cases.json", "fuzzingclient.json", "ws://127.0.0.1:12345", output, tt.prefixes...)
			if (err != nil) != tt.wantError {
				t.Fatalf("configure error=%v, want error=%v", err, tt.wantError)
			}
			if err != nil {
				return
			}
			got, err := loadJSON[suiteConfig](output)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Cases) != tt.wantCount {
				t.Fatalf("configured %d cases, want %d", len(got.Cases), tt.wantCount)
			}
		})
	}
}

func TestReadinessAndOriginLifetime(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	readyFile := filepath.Join(t.TempDir(), "ready.json")
	if err := writeJSON(readyFile, struct {
		Address string `json:"address"`
	}{listener.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct{ target string }{"socket": {listener.Addr().String()}, "ready file": {readyFile}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if err := run(t.Context(), []string{"wait", tt.target}); err != nil {
				t.Fatal(err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := waitReady(ctx, filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("cancelled readiness succeeded")
	}
	originFile := filepath.Join(t.TempDir(), "origin.json")
	if err := run(ctx, []string{"origin", "127.0.0.1:0", originFile}); err != nil {
		t.Fatal(err)
	}
	ready, err := loadJSON[struct {
		Address string `json:"address"`
	}](originFile)
	if err != nil || ready.Address == "" {
		t.Fatalf("origin readiness=%+v error=%v", ready, err)
	}
}

func TestInvalidCommands(t *testing.T) {
	tests := map[string]struct{ args []string }{
		"missing":               {},
		"unknown":               {[]string{"unknown"}},
		"wrong count":           {[]string{"origin"}},
		"invalid guard timeout": {[]string{"guard", "invalid", "1234"}},
		"invalid guard process": {[]string{"guard", "1", "0"}},
		"missing manifest":      {[]string{"verify", "missing", t.TempDir(), "summary.json"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if err := run(t.Context(), tt.args); err == nil {
				t.Fatal("invalid command succeeded")
			}
		})
	}
}

func TestTimeoutSecondsAndCancelledGuard(t *testing.T) {
	tests := map[string]struct {
		value     string
		want      int
		wantError bool
	}{
		"default": {"1800", 1800, false}, "maximum": {"86400", 86400, false},
		"zero": {"0", 0, true}, "negative": {"-1", 0, true},
		"too large": {"86401", 0, true}, "invalid": {"bad", 0, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := timeoutSeconds(tt.value)
			if got != tt.want || (err != nil) != tt.wantError {
				t.Fatalf("seconds=%d error=%v, want %d error=%v", got, err, tt.want, tt.wantError)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := run(ctx, []string{"guard", "60", "1234"}); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredAddress(t *testing.T) {
	tests := map[string]struct {
		host, port string
		want       string
		wantError  bool
	}{
		"IPv4":            {"127.0.0.1", "9001", "127.0.0.1:9001", false},
		"IPv6":            {"::1", "0", "[::1]:0", false},
		"empty host":      {"", "9001", "", true},
		"negative port":   {"127.0.0.1", "-1", "", true},
		"too large port":  {"127.0.0.1", "65536", "", true},
		"nonnumeric port": {"127.0.0.1", "invalid", "", true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := configuredAddress(tt.host, tt.port)
			if got != tt.want || (err != nil) != tt.wantError {
				t.Fatalf("address=%q error=%v, want %q error=%v", got, err, tt.want, tt.wantError)
			}
		})
	}
}
