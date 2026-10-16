// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build integration && (linux || darwin || freebsd || openbsd)

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
)

func TestTransparentCLI(t *testing.T) {
	t.Run("configuration and option defaults", func(t *testing.T) {
		confdir := t.TempDir()
		tests := map[string]struct{ mode string }{
			"regular": {"regular"}, "transparent": {"transparent"},
		}
		var baseline string
		for _, name := range []string{"regular", "transparent"} {
			listed, stderr, code := goRun(t, "--mode", tests[name].mode, "--set", "server=false", "--set", "confdir="+confdir, "--options")
			if code != 0 {
				t.Fatalf("%s configuration exit=%d: %s", name, code, stderr)
			}
			if name == "regular" {
				baseline = listed
				continue
			}
			// --options is the annotated default listing, not live mode metadata.
			if diff := gocmp.Diff(baseline, listed); diff != "" {
				t.Fatalf("transparent changed option defaults (-regular +transparent):\n%s", diff)
			}
		}
	})

	tests := map[string]struct{}{"eager": {}, "lazy": {}}
	for strategy := range tests {
		t.Run(strategy+" direct client fails closed", func(t *testing.T) {
			var contacted atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				contacted.Add(1)
				_, _ = io.WriteString(w, "direct request must not reach its Host destination")
			}))
			defer origin.Close()
			capture := filepath.Join(t.TempDir(), "flows.mitm")
			proxy, address, output := servingChild(t, "--mode", "transparent",
				"--set", "connection_strategy="+strategy, "--set", "save_stream_file="+capture)
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			client, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
			if err != nil && !errors.Is(err, syscall.ECONNRESET) {
				t.Fatal(err)
			}
			var reply []byte
			if client != nil {
				defer func() { _ = client.Close() }()
				deadline, _ := ctx.Deadline()
				if err := client.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				request := fmt.Sprintf("GET /direct HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", strings.TrimPrefix(origin.URL, "http://"))
				_, writeErr := io.WriteString(client, request)
				if writeErr != nil && !errors.Is(writeErr, syscall.EPIPE) && !errors.Is(writeErr, syscall.ECONNRESET) {
					t.Fatalf("direct client write: %v", writeErr)
				}
				var readErr error
				reply, readErr = io.ReadAll(client)
				if readErr != nil && !errors.Is(readErr, syscall.ECONNRESET) {
					t.Fatalf("direct client was not promptly refused: %v", readErr)
				}
			}
			if err := proxy.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			seen := <-output
			if err := proxy.Wait(); err != nil {
				t.Fatalf("transparent child did not exit with status 0: %v\n%s", err, seen)
			}
			if contacted.Load() != 0 {
				t.Fatal("transparent mode forwarded a direct client's Host destination")
			}
			file, err := os.Open(capture)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			var flows []*flow.HTTPFlow
			for recorded, err := range flowio.NewReader(file).All() {
				if err != nil {
					t.Fatal(err)
				}
				f, ok := recorded.(*flow.HTTPFlow)
				if !ok {
					t.Fatalf("unexpected refusal flow type %T", recorded)
				}
				flows = append(flows, f)
			}
			const refusal = "Request destination unknown. Unable to figure out where this request should be forwarded to."
			var lookupLine, denialLine string
			for line := range strings.SplitSeq(seen, "\n") {
				if strings.Contains(line, "Resolving transparent destination") {
					lookupLine = line
				}
				if strings.Contains(line, refusal) {
					denialLine = line
				}
			}
			flowReason := ""
			for _, f := range flows {
				if f.Error != nil && strings.Contains(f.Error.Msg, refusal) {
					flowReason = f.Error.Msg
				}
				if f.ServerConn != nil && f.ServerConn.Error != nil && strings.Contains(*f.ServerConn.Error, refusal) {
					flowReason = *f.ServerConn.Error
				}
			}
			addonDenied := denialLine != "" || flowReason != ""
			if (lookupLine != "") == addonDenied {
				t.Fatalf("want exactly lookup failure or addon denial, got CLI log:\n%s", seen)
			}
			if lookupLine != "" {
				if len(flows) != 0 || len(reply) != 0 {
					t.Fatalf("lookup refusal emitted flows=%d reply_bytes=%d", len(flows), len(reply))
				}
				t.Logf("observed=lookup-failure strategy=%s origin_requests=0 flows=0 reply_bytes=0 mitmdump_exit=0; %s", strategy, lookupLine)
				return
			}
			if strategy == "eager" {
				if denialLine == "" || len(flows) != 0 || len(reply) != 0 {
					t.Fatalf("eager addon denial emitted flows=%d reply_bytes=%d before protocol creation", len(flows), len(reply))
				}
			} else {
				if len(flows) != 1 {
					t.Fatalf("lazy addon denial emitted %d flows, want one failed HTTP flow", len(flows))
				}
				f := flows[0]
				if f.ServerConn == nil || f.ServerConn.Address == nil || f.ServerConn.Address.String() != address || f.ClientConn == nil || f.ClientConn.ProxyMode != "transparent" {
					t.Fatal("failed flow lost the captured direct-listener destination or mode")
				}
				if f.Request == nil || f.Request.Path != "/direct" || f.Response != nil && f.Response.StatusCode != http.StatusBadGateway {
					t.Fatal("saved direct-client exchange is not the failed request")
				}
				if flowReason == "" {
					t.Fatal("saved failed flow does not carry the addon refusal")
				}
				response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(reply)), nil)
				if err != nil {
					t.Fatalf("proxy-generated refusal response: %v", err)
				}
				body, readErr := io.ReadAll(response.Body)
				closeErr := response.Body.Close()
				if err := errors.Join(readErr, closeErr); err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), refusal) {
					t.Fatal("lazy direct-client response is not the proxy-generated addon refusal")
				}
			}
			t.Logf("observed=addon-denial strategy=%s origin_requests=0 flows=%d reply_bytes=%d mitmdump_exit=0; log=%s flow_error=%s", strategy, len(flows), len(reply), denialLine, flowReason)
		})
	}
}
