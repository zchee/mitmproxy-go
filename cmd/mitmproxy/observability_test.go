// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestObservabilityCLI(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "observability-cli")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	const injected = "v0.0.0-test.observability"
	build := exec.CommandContext(ctx, "go", "build", "-race", "-ldflags", "-X github.com/zchee/mitmproxy-go/internal/version.Version="+injected, "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build injected executable: %v\n%s", err, output)
	}
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"options_early_exit": {run: func(t *testing.T) {
				var exports atomic.Int64
				collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					exports.Add(1)
					w.WriteHeader(http.StatusOK)
				}))
				defer collector.Close()
				reserved, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := reserved.Close(); err != nil {
						t.Error(err)
					}
				}()
				for _, listing := range []string{"--options", "--commands"} {
					args := []string{"--set", "confdir=" + t.TempDir(), "--set", "mode=regular@" + reserved.Addr().String(), "--set", "otel_exporter_endpoint=" + collector.URL, "--set", "pprof_addr=" + reserved.Addr().String(), listing}
					childCtx, stop := context.WithTimeout(t.Context(), 30*time.Second)
					cmd := exec.CommandContext(childCtx, binary, args...) //nolint:gosec // The path is the executable built into this test's private directory.
					output, err := cmd.CombinedOutput()
					stop()
					if err != nil {
						t.Fatalf("%s early exit: %v\n%s", listing, err, output)
					}
					if listing == "--options" && !strings.Contains(string(output), "otel_exporter_endpoint") {
						t.Fatal("option listing omits the registered exporter control")
					}
					if len(output) == 0 {
						t.Fatalf("%s listing is empty", listing)
					}
				}
				if got := exports.Load(); got != 0 {
					t.Fatalf("metadata exits started exporter I/O: %d requests", got)
				}
			}},
			"version_injected": {run: func(t *testing.T) {
				var exports atomic.Int64
				collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { exports.Add(1); w.WriteHeader(http.StatusOK) }))
				defer collector.Close()
				childCtx, stop := context.WithTimeout(t.Context(), 30*time.Second)
				defer stop()
				cmd := exec.CommandContext(childCtx, binary, "--set", "otel_exporter_endpoint="+collector.URL, "--set", "pprof_addr="+strings.TrimPrefix(collector.URL, "http://"), "--version") //nolint:gosec // The path is the executable built into this test's private directory.
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("version exit: %v\n%s", err, output)
				}
				if got := exports.Load(); got != 0 {
					t.Fatalf("version exit started exporter I/O: %d requests", got)
				}
				if !strings.Contains(string(output), "Mitmproxy-go: "+injected) {
					t.Fatalf("injected version missing from output: %s", output)
				}
			}},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}
