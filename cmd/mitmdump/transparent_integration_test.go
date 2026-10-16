// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build integration && (linux || darwin || freebsd || openbsd)

package main

import (
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
				reply, readErr := io.ReadAll(client)
				if readErr != nil && !errors.Is(readErr, syscall.ECONNRESET) {
					t.Fatalf("direct client was not promptly refused: %v", readErr)
				}
				if len(reply) != 0 {
					t.Fatalf("non-redirected client received %d application bytes", len(reply))
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
			for _, err := range flowio.NewReader(file).All() {
				if err != nil {
					t.Fatal(err)
				}
				t.Fatal("direct-client refusal published a flow without a usable original destination")
			}
			t.Logf("transparent startup succeeded; direct client refused; origin requests=0; emitted flows=0; mitmdump exit=0; CLI log:\n%s", seen)
		})
	}
}
