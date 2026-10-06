// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build unix

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/flowio/har"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

// writeReplayFile serializes complete flows for the production file loader.
func writeReplayFile(t *testing.T, flows ...*flow.HTTPFlow) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "replay.mitm")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := flowio.NewWriter(file)
	for _, f := range flows {
		if err := writer.Add(f); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// servingChild waits for the actual listener announcement, not a fixed delay.
func servingChild(t *testing.T, args ...string) (*exec.Cmd, string, <-chan string) {
	t.Helper()
	cmd := child(t, append([]string{"--listen-host", "127.0.0.1", "-p", "0"}, args...)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	ready, output := make(chan string, 1), make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		var seen strings.Builder
		listening := false
		for scanner.Scan() {
			seen.WriteString(scanner.Text())
			seen.WriteByte('\n')
			if !listening {
				if match := listeningAddr.FindStringSubmatch(scanner.Text()); match != nil {
					listening = true
					ready <- match[1]
				}
			}
		}
		if !listening {
			close(ready)
		}
		if err := scanner.Err(); err != nil {
			seen.WriteString(err.Error())
		}
		output <- seen.String()
	}()
	addr, ok := <-ready
	if !ok {
		t.Fatalf("child ended before listening:\n%s", <-output)
	}
	return cmd, addr, output
}

func stopServingChild(t *testing.T, cmd *exec.Cmd, output <-chan string) {
	t.Helper()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	seen := <-output
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child did not exit with status 0: %v\n%s", err, seen)
	}
}

func TestClientReplayBinary(t *testing.T) {
	type requestRow struct {
		Method, Target, Protocol, Host string
		Headers                        http.Header
		Body                           string
	}
	tests := map[string]struct {
		method, path, body string
	}{
		"success: empty request": {"GET", "/empty?recorded=yes", ""},
		"success: post body":     {"POST", "/post", "recorded post body"},
		"success: binary body":   {"PATCH", "/binary", "\x00\xffrecorded\r\n"},
	}
	seen := make(chan requestRow, len(tests))
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read replay body: %v", err)
		}
		select {
		case seen <- requestRow{r.Method, r.RequestURI, r.Proto, r.Host, r.Header.Clone(), string(body)}:
		default:
			t.Error("unexpected additional client replay request")
		}
		_, _ = io.WriteString(w, "origin response")
	}))
	defer origin.Close()
	var flows []*flow.HTTPFlow
	var want []requestRow
	for _, name := range slices.Sorted(maps.Keys(tests)) {
		tt := tests[name]
		f := testflow.TFlow(testflow.WithResponse)
		f.Live = false
		headers := httpmsg.Headers{
			{Name: []byte("Host"), Value: []byte(strings.TrimPrefix(origin.URL, "http://"))},
			{Name: []byte("X-Recorded"), Value: []byte(name)},
			{Name: []byte("X-Repeated"), Value: []byte("first")},
			{Name: []byte("X-Repeated"), Value: []byte("second")},
		}
		var err error
		f.Request, err = httpmsg.MakeRequest(tt.method, origin.URL+tt.path, []byte(tt.body), headers)
		if err != nil {
			t.Fatal(err)
		}
		flows = append(flows, f)
		want = append(want, requestRow{tt.method, tt.path, "HTTP/1.1", strings.TrimPrefix(origin.URL, "http://"), http.Header{
			"Content-Length": {fmt.Sprint(len(tt.body))},
			"X-Recorded":     {name},
			"X-Repeated":     {"first", "second"},
		}, tt.body})
	}
	out, stderr, code := goRun(t, "-n", "-C", writeReplayFile(t, flows...))
	if code != 0 {
		t.Fatalf("client replay exited %d: stdout %s, stderr %s", code, out, stderr)
	}
	var got []requestRow
	for range len(want) {
		select {
		case row := <-seen:
			got = append(got, row)
		default:
			t.Fatalf("binary exited before replaying every flow: got %d of %d\n%s", len(got), len(want), out)
		}
	}
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Fatalf("origin requests (-recorded +replayed):\n%s", diff)
	}
	if len(seen) != 0 {
		t.Fatal("binary replayed a request more than once")
	}
}

func TestServerReplayBinary(t *testing.T) {
	var contacted atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		contacted.Add(1)
		http.Error(w, "server replay must not contact the origin", http.StatusBadGateway)
	}))
	defer origin.Close()
	f := testflow.TFlow(testflow.WithResponse)
	f.Live = false
	var err error
	f.Request, err = httpmsg.MakeRequest("POST", origin.URL+"/recorded?value=yes", []byte("recorded request"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.Response, err = httpmsg.MakeResponse(http.StatusCreated, []byte("recorded response\x00"), httpmsg.Headers{
		{Name: []byte("X-Recorded-Response"), Value: []byte("from file")},
	})
	if err != nil {
		t.Fatal(err)
	}
	cmd, addr, output := servingChild(t, "-S", writeReplayFile(t, f))
	proxyURL := &url.URL{Scheme: "http", Host: addr}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", f.Request.URL(), strings.NewReader("recorded request"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated || resp.Header.Get("X-Recorded-Response") != "from file" {
		t.Fatalf("replayed response status=%d headers=%v", resp.StatusCode, resp.Header)
	}
	if diff := gocmp.Diff(string(f.Response.RawContent), string(body)); diff != "" {
		t.Fatalf("response body (-recorded +replayed):\n%s", diff)
	}
	transport.CloseIdleConnections()
	stopServingChild(t, cmd, output)
	if contacted.Load() != 0 {
		t.Fatal("server replay contacted the origin")
	}
}

func TestHARAndRewriteOptionsBinary(t *testing.T) {
	tests := map[string]struct{ option string }{
		"success: header option": {option: "modify_headers=/x/y"},
		"success: map option":    {option: "map_remote=|a|b"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "HAR response")
			}))
			defer origin.Close()
			path := filepath.Join(t.TempDir(), "capture.har")
			cmd, addr, output := servingChild(t, "--set", "hardump="+path, "--set", tt.option)
			transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr})}
			defer transport.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "POST", origin.URL+"/probe", strings.NewReader("HAR request"))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := (&http.Client{Transport: transport}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK || string(body) != "HAR response" {
				t.Fatalf("proxy response: status %d body %q error %v", resp.StatusCode, body, err)
			}
			transport.CloseIdleConnections()
			stopServingChild(t, cmd, output)
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			entries, err := har.ReadEntries(file)
			if err != nil || len(entries) != 1 {
				t.Fatalf("read HAR: entries=%d error=%v", len(entries), err)
			}
			f, err := har.RequestToFlow(entries[0])
			if err != nil {
				t.Fatal(err)
			}
			if f.Request.URL() != origin.URL+"/probe" || string(f.Request.RawContent) != "HAR request" || f.Response == nil || string(f.Response.RawContent) != "HAR response" {
				t.Fatalf("HAR did not preserve request and response: %+v", f)
			}
		})
	}
}
