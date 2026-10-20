// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build (difftest || browser || webprivileged) && unix

package acceptance_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const webTestPassword = "mitmweb-acceptance-nonsecret"

type webInputTuple struct {
	webPort int
	confdir string
	fixture string
}

func newWebInputTuple(t *testing.T, fixture string) webInputTuple {
	t.Helper()
	// This is an ownership probe, never permission to stop another listener.
	proxy, err := net.Listen("tcp4", "127.0.0.1:18080")
	if err != nil {
		t.Fatalf("fixed proxy port is already owned: %v", err)
	}
	defer func() {
		if err := proxy.Close(); err != nil {
			t.Errorf("close proxy ownership probe: %v", err)
		}
	}()
	web, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := web.Close(); err != nil {
			t.Errorf("close web ownership probe: %v", err)
		}
	}()
	confdir := filepath.Join(t.TempDir(), "conf")
	if err := os.Mkdir(confdir, 0o700); err != nil {
		t.Fatal(err)
	}
	tuple := webInputTuple{web.Addr().(*net.TCPAddr).Port, confdir, fixture}
	if tuple.webPort == 18080 {
		t.Fatal("web port aliases the owned proxy port")
	}
	resetWebConfdir(t, tuple)
	return tuple
}

func resetWebConfdir(t *testing.T, tuple webInputTuple) {
	t.Helper()
	root, err := os.OpenRoot(tuple.confdir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Errorf("close owned confdir: %v", err)
		}
	}()
	entries, err := os.ReadDir(tuple.confdir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := root.RemoveAll(entry.Name()); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(tuple.confdir, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err = os.ReadDir(tuple.confdir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("confdir reset did not reproduce the frozen empty inventory: entries=%v err=%v", entries, err)
	}
	info, err := os.Stat(tuple.confdir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("confdir reset did not preserve mode 0700: %v", err)
	}
	t.Logf("confdir=%s initial_files=0 restored_files=0 mode=0700", tuple.confdir)
}

func (tuple webInputTuple) goArgs() []string {
	args := []string{"--mode", "regular@127.0.0.1:18080", "--no-web-open-browser", "--web-host=127.0.0.1", "--web-port=" + strconv.Itoa(tuple.webPort), "--set", "confdir=" + tuple.confdir, "--set", "web_password=" + webTestPassword}
	if tuple.fixture != "" {
		args = append(args, "-r", tuple.fixture)
	}
	return args
}

func webClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Jar: jar, Transport: transport, Timeout: 10 * time.Second}
}

func requestWeb(ctx context.Context, client *http.Client, tuple webInputTuple, method, path string, body []byte, contentTypes ...string) (int, string, []byte, error) {
	if len(contentTypes) > 1 {
		return 0, "", nil, errors.New("at most one request content type is allowed")
	}
	request, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("http://127.0.0.1:%d%s", tuple.webPort, path), bytes.NewReader(body))
	if err != nil {
		return 0, "", nil, err
	}
	request.Header.Set("Authorization", "Bearer "+webTestPassword)
	if body != nil {
		contentType := "application/octet-stream"
		if len(contentTypes) == 1 {
			contentType = contentTypes[0]
		}
		request.Header.Set("Content-Type", contentType)
	}
	for _, cookie := range client.Jar.Cookies(request.URL) {
		if cookie.Name == "_mitmproxy_xsrf" {
			request.Header.Set("X-XSRFToken", cookie.Value)
		}
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, "", nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (64<<20)+1))
	err = errors.Join(err, response.Body.Close())
	if err == nil && len(raw) > 64<<20 {
		err = errors.New("acceptance response exceeds 64 MiB")
	}
	return response.StatusCode, response.Header.Get("Content-Type"), raw, err
}

func verifyWebPortsReleased(t *testing.T, tuple webInputTuple) {
	t.Helper()
	for _, port := range []int{18080, tuple.webPort} {
		listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("owned port %d not released after process reap: %v", port, err)
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		t.Logf("owned_port=%d rebound=true released=true", port)
	}
}
