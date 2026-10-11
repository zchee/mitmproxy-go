// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build windows

package freeport

import (
	"errors"
	"fmt"
	"net"
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
		if mode == "stall" {
			if err := stallWindowsRangeFixture(os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]); err != nil {
				_, _ = fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		if mode == "command failure" {
			os.Exit(1)
		}
		output := "invalid netsh output\n"
		protocol := os.Args[len(os.Args)-1]
		if os.Args[len(os.Args)-2] == "dynamicportrange" {
			output = "Protocol Dynamic Port Range\nStart Port : 49152\nNumber of Ports : 16384\n"
			if mode == "malformed bounds" || mode == "malformed all bounds" {
				output = "Start Port : invalid\nNumber of Ports : 16384\n"
			} else if mode == "disjoint" {
				output = "Start Port : 49152\nNumber of Ports : 100\n"
				if protocol == "protocol=udp" {
					output = "Start Port : 50000\nNumber of Ports : 100\n"
				}
			}
		} else if mode != "parse failure" {
			output = "Protocol Port Exclusion Ranges\nStart Port End Port\n---------- --------\n"
			switch mode {
			case "both", "malformed all bounds":
				output += "1 65535\n"
			case "tcp only":
				if protocol == "protocol=tcp" {
					output += "49152 55000\n"
				}
			case "udp only":
				if protocol == "protocol=udp" {
					output += "1 65535\n"
				}
			case "wide":
				if protocol == "protocol=udp" {
					output += "49152 60000\n"
				}
			case "overlap":
				output += "49152 55000\n"
				if protocol == "protocol=udp" {
					output += "54000 60000\n"
				}
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

func TestWindowsListenPairDomains(t *testing.T) {
	if mode := os.Getenv("MITMPROXY_FREEPORT_FIXTURE"); mode != "" {
		tcp, udp, err := ListenPair(t.Context(), "tcp4", "127.0.0.1:0")
		if mode == "both" || mode == "udp only" || mode == "disjoint" || mode == "malformed all bounds" {
			if tcp != nil || udp != nil || err == nil {
				t.Fatalf("empty domain returned sockets: %v %v %v", tcp, udp, err)
			}
			if _, ok := errors.AsType[*net.OpError](err); !ok {
				t.Fatalf("domain failure is not typed: %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tcp.Close() }()
		defer func() { _ = udp.Close() }()
		if tcp.Addr().String() != udp.LocalAddr().String() {
			t.Fatalf("paired addresses differ: %s %s", tcp.Addr(), udp.LocalAddr())
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		domain, err := pairPortDomain(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if domain.available && (port < domain.bounds.first || port > domain.bounds.last || inPortRanges(port, domain.excluded)) {
			t.Fatalf("candidate %d outside readable complement: %+v", port, domain)
		}
		if !domain.available && (domain.bounds != (portRange{first: 49152, last: 65535}) || port < 49152 || port > 65535) {
			t.Fatalf("unavailable domain did not use the IANA dynamic range: port=%d domain=%+v", port, domain)
		}
		t.Logf("paired port=%d dynamic=%+v excluded=%+v domain_available=%t", port, domain.bounds, domain.excluded, domain.available)
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
		"error: known exclusions without bounds": {mode: "malformed all bounds"},
		"error: all protocols excluded":          {mode: "both"},
		"error: UDP excluded":                    {mode: "udp only"},
		"error: disjoint dynamic domains":        {mode: "disjoint"},
		"success: TCP exclusion":                 {mode: "tcp only"},
		"success: wide UDP exclusion":            {mode: "wide"},
		"success: overlapping exclusions":        {mode: "overlap"},
		"success: empty tables":                  {mode: "empty"},
		"success: command fallback":              {mode: "command failure"},
		"success: parse fallback":                {mode: "parse failure"},
		"success: unavailable dynamic bounds":    {mode: "malformed bounds"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestWindowsListenPairDomains$", "-test.v")
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "MITMPROXY_FREEPORT_FIXTURE="+test.mode)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("paired domain subprocess: %v\n%s", err, output)
			}
			t.Logf("%s", output)
		})
	}
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
