// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build windows

package freeport

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain supplies a netsh command fixture in isolated child processes.
func TestMain(m *testing.M) {
	executable, err := os.Executable()
	if err == nil && strings.EqualFold(filepath.Base(executable), "netsh.exe") && os.Getenv("MITMPROXY_FREEPORT_FIXTURE") != "" {
		mode := os.Getenv("MITMPROXY_FREEPORT_FIXTURE")
		if mode == "command failure" {
			os.Exit(1)
		}
		output := "invalid netsh output\n"
		if mode != "parse failure" {
			output = "Protocol Port Exclusion Ranges\nStart Port End Port\n---------- --------\n"
			if mode != "empty" && (mode != "udp only" || os.Args[len(os.Args)-1] == "protocol=udp") {
				output += "1 65535\n"
			}
			output += "\n* - Administered port exclusions.\n"
		}
		if _, err := fmt.Fprint(os.Stdout, output); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestWindowsExcludedCandidates is a regression row using real socket selection
// against an excluded-range command fixture, not absent production identifiers.
func TestWindowsExcludedCandidates(t *testing.T) {
	if mode := os.Getenv("MITMPROXY_FREEPORT_FIXTURE"); mode != "" {
		paired, err := FreePort()
		blocked := mode == "both" || mode == "udp only"
		if blocked {
			if paired != 0 || err == nil {
				t.Fatalf("selected excluded candidate %d, error=%v; fixture excludes ports 1..65535", paired, err)
			}
		} else if paired == 0 || err != nil {
			t.Fatalf("fallback/empty selection = %d, %v", paired, err)
		}
		tcp := GetFreeTCPPort()
		if (tcp == 0) != (mode == "both") {
			t.Fatalf("TCP-only selection=%d for fixture %q", tcp, mode)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "netsh.exe"), binary, 0o700); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct{ mode string }{
		"error: both protocols excluded": {mode: "both"},
		"error: UDP-only exclusion":      {mode: "udp only"},
		"success: no exclusions":         {mode: "empty"},
		"success: command fallback":      {mode: "command failure"},
		"success: parse fallback":        {mode: "parse failure"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestWindowsExcludedCandidates$")
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "MITMPROXY_FREEPORT_FIXTURE="+tt.mode)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("excluded-range subprocess: %v\n%s", err, output)
			}
		})
	}
}
