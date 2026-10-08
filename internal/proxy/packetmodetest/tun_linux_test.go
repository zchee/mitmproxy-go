// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build packetmodes && linux

package packetmodetest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
)

func packetBinary(t *testing.T) string {
	t.Helper()
	path := os.Getenv("PACKET_GATE_BINARY")
	if path == "" {
		t.Fatal("required PACKET_GATE_BINARY is missing")
	}
	if info, err := os.Stat(path); err != nil || info.Size() == 0 {
		t.Fatalf("missing mitmdump binary %s: %v", path, err)
	}
	return path
}

func TestTunCreated(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("required TUN creation acceptance must run under sudo")
	}
	tests := map[string]struct{ mode string }{
		"success: anonymous interface binds loopback HTTP without a route": {mode: "tun"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			const response = "packet-source HTTP response"
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, response)
			}))
			defer origin.Close()
			directory := privateDirectory(t)
			flows := filepath.Join(directory, "flows.mitm")
			p := startProcess(t, packetBinary(t), []string{"--mode", tt.mode, "--set", "confdir=" + directory, "--set", "save_stream_file=" + flows}, nil, "tun-created-proxy.log")
			name := p.ready(t, `TUN interface created: ([A-Za-z0-9_-]+)`)
			paths := map[string]string{
				"net/ipv4/conf/" + name + "/rp_filter": "0", "net/ipv4/conf/all/rp_filter": "0",
				"net/ipv4/conf/" + name + "/route_localnet": "1", "net/ipv4/conf/" + name + "/accept_local": "1",
			}
			for path, want := range paths {
				content, err := os.ReadFile(filepath.Join("/proc/sys", path))
				if err != nil || strings.TrimSpace(string(content)) != want {
					t.Fatalf("%s = %q, %v; want %q", path, content, err, want)
				}
			}
			routesBefore := runCommand(t, "ip", "route", "show", "table", "all")
			body := runCommand(t, "curl", "--noproxy", "*", "--interface", name, "--max-time", "30", "--fail", "--silent", "--show-error", origin.URL+"/tun")
			if diff := gocmp.Diff(response, body); diff != "" {
				t.Fatalf("origin reply (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(routesBefore, runCommand(t, "ip", "route", "show", "table", "all")); diff != "" {
				t.Fatalf("acceptance added a route (-before +after):\n%s", diff)
			}
			p.stop(t)
			file, err := os.Open(flows)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			host, port := address(t, strings.TrimPrefix(origin.URL, "http://"))
			var found int
			for recorded, err := range flowio.NewReader(file).All() {
				if err != nil {
					t.Fatal(err)
				}
				f, ok := recorded.(*flow.HTTPFlow)
				if !ok {
					t.Fatalf("TUN recorded %T, want HTTP", recorded)
				}
				if diff := gocmp.Diff(&connection.Address{Host: host, Port: port}, f.ServerConn.Address); diff != "" {
					t.Fatalf("captured destination (-want +got):\n%s", diff)
				}
				if f.Response == nil || f.Error != nil {
					t.Fatalf("incomplete TUN flow: response=%v error=%v", f.Response, f.Error)
				}
				content, err := f.Response.Content()
				if err != nil || string(content) != response {
					t.Fatalf("recorded TUN response = %q, %v", content, err)
				}
				found++
			}
			if found != 1 {
				t.Fatalf("recorded HTTP flows = %d, want 1", found)
			}
			if _, err := os.Stat(filepath.Join("/sys/class/net", name)); !os.IsNotExist(err) {
				t.Fatalf("created interface remains after process exit: %v", err)
			}
		})
	}
}

func TestTunPersistent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("persistent reattachment must run as the unprivileged runner user")
	}
	before := tunSnapshot(t)
	tests := map[string]struct{ label string }{
		"success: first unprivileged attachment": {label: "tun-attach-first.log"},
		"success: reattach after previous stop":  {label: "tun-attach-second.log"},
	}
	// Both rows run serially against the same pre-created interface.
	for _, name := range []string{"success: first unprivileged attachment", "success: reattach after previous stop"} {
		tt := tests[name]
		t.Run(name, func(t *testing.T) {
			directory := privateDirectory(t)
			p := startProcess(t, packetBinary(t), []string{"--mode", "tun:tun0", "--set", "confdir=" + directory}, nil, tt.label)
			if name := p.ready(t, `TUN interface created: ([A-Za-z0-9_-]+)`); name != "tun0" {
				t.Fatalf("reattached interface = %q, want tun0", name)
			}
			if diff := gocmp.Diff(before, tunSnapshot(t)); diff != "" {
				t.Fatalf("fallback changed interface configuration (-before +after):\n%s", diff)
			}
			p.stop(t)
			if diff := gocmp.Diff(before, tunSnapshot(t)); diff != "" {
				t.Fatalf("stop changed persistent configuration (-before +after):\n%s", diff)
			}
		})
	}
}

func runCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, output)
	}
	return string(output)
}

func tunSnapshot(t *testing.T) map[string]string {
	t.Helper()
	values := map[string]string{
		"addresses": runCommand(t, "ip", "-o", "address", "show", "dev", "tun0"),
	}
	mtu, err := os.ReadFile("/sys/class/net/tun0/mtu")
	if err != nil {
		t.Fatal(err)
	}
	values["mtu"] = string(mtu)
	if !strings.Contains(runCommand(t, "ip", "-o", "link", "show", "dev", "tun0"), "UP") {
		t.Fatal("persistent interface is not administratively up")
	}
	values["administratively up"] = "true"
	entries, err := os.ReadDir("/proc/sys/net/ipv4/conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		for _, name := range []string{"rp_filter", "route_localnet", "accept_local"} {
			path := filepath.Join("/proc/sys/net/ipv4/conf", entry.Name(), name)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			values[path] = string(content)
		}
	}
	return values
}
