//go:build integration

// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"bytes"
	"context"
	json "encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestMitmwebCLI(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "mitmweb")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build real executable: %v\n%s", err, output)
	}
	tests := map[string]struct{ run func(*testing.T, string) }{
		"http_control": {run: testMitmwebControl},
		"early_exit":   {run: testMitmwebEarlyExit},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) { tt.run(t, binary) })
	}
}

func testMitmwebEarlyExit(t *testing.T, binary string) {
	t.Helper()
	tests := map[string]struct {
		args   []string
		want   string
		prefix string
	}{
		"options":        {args: []string{"--options"}, want: "web_theme", prefix: "\n# "},
		"commands":       {args: []string{"--commands"}, want: "view.flows", prefix: "browser.start "},
		"version":        {args: []string{"--version"}, want: "Mitmproxy-go:", prefix: "Mitmproxy-go:"},
		"completion":     {args: []string{"completion", "bash"}, want: "__start_mitmweb", prefix: "# bash completion V2 for mitmweb"},
		"complete_flags": {args: []string{"__complete", "--web-"}, want: "--web-port", prefix: "--web-"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := listener.Close(); err != nil {
					t.Error(err)
				}
			}()
			args := tt.args
			if name != "completion" && name != "complete_flags" {
				args = append([]string{"--web-port", fmt.Sprint(listener.Addr().(*net.TCPAddr).Port), "--set", "confdir=" + t.TempDir()}, args...)
			}
			cmd := exec.CommandContext(t.Context(), binary, args...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("early exit %q: %v\nstdout=%s\nstderr=%s", args, err, output, stderr.String())
			}
			if tt.prefix != "" && !strings.HasPrefix(string(output), tt.prefix) {
				t.Fatalf("diagnostics preceded machine-readable stdout; expected prefix %q", tt.prefix)
			}
			if !strings.Contains(string(output), tt.want) {
				t.Fatalf("missing %q: %s", tt.want, output)
			}
		})
	}
}

func testMitmwebControl(t *testing.T, binary string) {
	t.Helper()
	requests := make(chan string, 2)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.URL.Path
		_, _ = io.WriteString(w, "real replay response")
	}))
	defer origin.Close()
	f := testflow.TFlow(testflow.WithResponse)
	f.ID = "42"
	if err := f.Request.SetURL(origin.URL + "/replayed"); err != nil {
		t.Fatal(err)
	}
	f.Request.SetHostHeader(strings.TrimPrefix(origin.URL, "http://"))
	flowfile := filepath.Join(t.TempDir(), "input.mitm")
	file, err := os.OpenFile(flowfile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := flowio.NewWriter(file).Add(f); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--no-web-open-browser", "--web-host", "127.0.0.1", "--web-port", "0", "--set", "mode=regular@127.0.0.1:0", "--set", "confdir="+t.TempDir(), "--set", "web_password=cli-fixture", "-r", flowfile)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() { cancel(); _ = cmd.Process.Kill() }()
	addresses := make(chan string, 1)
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if _, after, ok := strings.Cut(scanner.Text(), "Web server listening at "); ok {
				if fields := strings.Fields(after); len(fields) > 0 {
					select {
					case addresses <- strings.Trim(fields[0], "\""):
					default:
					}
				}
			}
		}
	}()
	var address string
	select {
	case address = <-addresses:
	case err := <-done:
		t.Fatalf("binary exited before readiness: %v stderr=%s", err, stderr.String())
	case <-ctx.Done():
		t.Fatal("binary never announced its actual web listener")
	}
	base, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	if base.Port() == "0" || base.Query().Get("token") != "" {
		t.Fatalf("unexpected fixed-password listener URL shape")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Transport: &http.Transport{Proxy: nil}, Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	request := func(method, path, body, password string) (int, []byte) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(address, "/")+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+password)
		r.Header.Set("Content-Type", "application/json")
		for _, cookie := range jar.Cookies(base) {
			if cookie.Name == "_mitmproxy_xsrf" {
				r.Header.Set("X-XSRFToken", cookie.Value)
			}
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("read=%v close=%v", err, closeErr)
		}
		return response.StatusCode, data
	}
	if status, _ := request("GET", "/", "", "wrong"); status != 403 {
		t.Fatalf("wrong authentication status=%d", status)
	}
	if status, _ := request("GET", "/", "", "cli-fixture"); status != 200 {
		t.Fatalf("correct authentication status=%d", status)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, data := request("GET", "/flows", "", "cli-fixture")
		if status != 200 {
			t.Fatalf("flow list status=%d", status)
		}
		if bytes.Contains(data, []byte(`"id":"42"`)) {
			break
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("actual rfile loader never populated web view")
		}
	}
	if status, body := request("PUT", "/flows/42", `{"comment":"edited from CLI"}`, "cli-fixture"); status != 200 || len(body) != 0 {
		t.Fatalf("edit status=%d body=%s", status, body)
	}
	status, data := request("GET", "/flows", "", "cli-fixture")
	var flows []map[string]any
	if err := json.Unmarshal(data, &flows); err != nil {
		t.Fatal(err)
	}
	if status != 200 || len(flows) != 1 {
		t.Fatalf("edited flow list status=%d len=%d", status, len(flows))
	}
	if diff := gocmp.Diff("edited from CLI", flows[0]["comment"]); diff != "" {
		t.Fatalf("comment (-want +got):\n%s", diff)
	}
	if status, data := request("POST", "/flows/42/replay", "", "cli-fixture"); status != 200 {
		t.Fatalf("replay status=%d body=%s", status, data)
	}
	select {
	case path := <-requests:
		if path != "/replayed" {
			t.Fatalf("origin path=%q", path)
		}
	case <-ctx.Done():
		t.Fatal("real replay did not reach owned origin")
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("signal shutdown: %v stderr=%s", err, stderr.String())
		}
	case <-ctx.Done():
		t.Fatal("binary did not join signal shutdown")
	}
	select {
	case <-scanned:
	case <-ctx.Done():
		t.Fatal("stdout scanner did not finish")
	}
	if conn, err := net.DialTimeout("tcp", base.Host, time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("web listener survived process shutdown")
	}
}
