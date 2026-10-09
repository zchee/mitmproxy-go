// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build packetmodes && linux

package packetmodetest

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/local"
)

func TestLinuxLocalExecutable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("local mode acceptance must run as the runner user")
	}
	primary := net.ParseIP(os.Getenv("PACKET_GATE_LOCAL_ADDRESS"))
	if primary == nil || primary.To4() == nil || primary.IsLoopback() || primary.IsUnspecified() {
		t.Fatal("PACKET_GATE_LOCAL_ADDRESS must be the runner's primary nonloopback IPv4 address")
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(primary.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	const reply = "native local origin response"
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, reply)
	}))
	origin.Listener = listener
	origin.Start()
	defer origin.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	directory := privateDirectory(t)
	flows := filepath.Join(directory, "flows.mitm")
	p := startProcess(t, packetBinary(t), []string{"--mode", "local:curl", "--set", "confdir=" + directory, "--set", "save_stream_file=" + flows}, nil, "local-proxy.log")
	p.ready(t, `(Local redirector started\.)`)
	base := "http://example.test:" + strconv.Itoa(port)
	tests := map[string]struct {
		command string
		args    []string
	}{
		"success: curl process intercepted": {command: "curl", args: []string{"--noproxy", "*", "--max-time", "30", "--fail", "--silent", "--show-error", base + "/curl"}},
		"success: wget process bypasses":    {command: "wget", args: []string{"--no-proxy", "--timeout=30", "--tries=1", "--quiet", "--output-document=-", base + "/wget"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(reply, runCommand(t, tt.command, tt.args...)); diff != "" {
				t.Fatalf("origin reply (-want +got):\n%s", diff)
			}
		})
	}
	p.stop(t)
	file, err := os.Open(flows)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	count := 0
	for recorded, err := range flowio.NewReader(file).All() {
		if err != nil {
			t.Fatal(err)
		}
		f, ok := recorded.(*flow.HTTPFlow)
		if !ok || f.Request == nil || f.Response == nil || f.Error != nil {
			t.Fatalf("local flow is not a complete HTTP exchange: %v", recorded)
		}
		if f.Request.Path != "/curl" {
			t.Fatalf("unexpected intercepted request %q; wget must bypass", f.Request.Path)
		}
		if diff := gocmp.Diff(&connection.Address{Host: primary.String(), Port: port}, f.ServerConn.Address); diff != "" {
			t.Fatalf("local captured destination (-want +got):\n%s", diff)
		}
		if f.ClientConn.GetState().Has("pid") || f.ClientConn.GetState().Has("process_name") || f.Metadata.Has("pid") || f.Metadata.Has("process_name") {
			t.Fatal("Linux local flow unexpectedly has process attribution")
		}
		count++
	}
	if count != 1 {
		t.Fatalf("captured HTTP flows = %d, want curl only", count)
	}
}

func TestLinuxLocalSudoFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("privilege probe refusal must run as the runner user")
	}
	tests := map[string]struct{ code int }{
		"error: PATH sudo refuses elevation": {code: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			directory := privateDirectory(t)
			stub := filepath.Join(directory, "sudo")
			if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit "+strconv.Itoa(tt.code)+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			// Acquire the real pinned artifact before substituting sudo, so an
			// unrelated download error cannot masquerade as privilege refusal.
			if _, err := local.AcquireArtifact(ctx, directory, "", "linux", "amd64"); err != nil {
				t.Fatalf("required native redirector artifact: %v", err)
			}
			command := exec.CommandContext(ctx, packetBinary(t), "--mode", "local", "--set", "confdir="+directory)
			command.Env = append(os.Environ(), "PATH="+directory+":"+os.Getenv("PATH"))
			output, err := command.CombinedOutput()
			if writeErr := os.WriteFile(logPath(t, "local-sudo-refusal.log"), output, 0o644); writeErr != nil {
				t.Fatal(writeErr)
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("local sudo refusal exit = %v; want 1\n%s", err, output)
			}
			if !strings.Contains(string(output), "Failed to elevate privileges") {
				t.Fatalf("local refusal missing upstream text\n%s", output)
			}
		})
	}
}
