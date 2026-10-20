// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestMain(m *testing.M) {
	if path := os.Getenv("MITMPROXY_WEB_BROWSER_RECORD"); path != "" {
		data, err := json.Marshal(os.Args[1:])
		if err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			os.Exit(2)
		}
		if os.Getenv("MITMPROXY_WEB_BROWSER_FAIL") != "" {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestWebBrowserOpen(t *testing.T) {
	tests := map[string]struct{ installed, fail, canceled bool }{
		"argv":     {installed: true},
		"failure":  {installed: true, fail: true},
		"headless": {},
		"canceled": {installed: true, canceled: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			record := filepath.Join(t.TempDir(), "argv.json")
			t.Setenv("PATH", dir)
			t.Setenv("MITMPROXY_WEB_BROWSER_RECORD", record)
			t.Setenv("MITMPROXY_WEB_BROWSER_FAIL", "")
			if tt.fail {
				t.Setenv("MITMPROXY_WEB_BROWSER_FAIL", "1")
			}
			if tt.installed {
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				command := "wslview"
				if runtime.GOOS == "darwin" {
					command = "open"
				}
				if runtime.GOOS == "windows" {
					command = "rundll32.exe"
				}
				if err := os.Symlink(executable, filepath.Join(dir, command)); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.canceled {
				cancel()
			}
			address := "http://[::1]:8081/?token=literal%20value&x=$(touch should-not-run)"
			got := openBrowser(ctx, address)
			if want := tt.installed && !tt.fail && !tt.canceled; got != want {
				t.Fatalf("open=%t want=%t", got, want)
			}
			data, err := os.ReadFile(record)
			if !tt.installed || tt.canceled {
				if !os.IsNotExist(err) {
					t.Fatalf("unexpected recorder launch: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var args []string
			if err := json.Unmarshal(data, &args); err != nil {
				t.Fatal(err)
			}
			want := []string{address}
			if runtime.GOOS == "windows" {
				want = []string{"url.dll,FileProtocolHandler", address}
			}
			if diff := gocmp.Diff(want, args); diff != "" {
				t.Fatalf("argv (-want +got):\n%s", diff)
			}
		})
	}
	t.Run("messages", func(t *testing.T) {
		tests := map[string]struct {
			password string
			hint     bool
		}{"random_token": {hint: true}, "fixed_password": {password: "not-for-logs"}}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				t.Setenv("PATH", t.TempDir())
				m := newWebMaster(t)
				if err := m.Do(t.Context(), func(ctx context.Context) error {
					return m.Options.Update(ctx, map[string]any{"web_open_browser": true, "web_password": tt.password})
				}); err != nil {
					t.Fatal(err)
				}
				r, w, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := r.Close(); err != nil {
						t.Error(err)
					}
				}()
				m.logger = slog.New(slog.NewTextHandler(w, nil))
				logs := make(chan []byte, 1)
				go func() { data, _ := io.ReadAll(r); logs <- data }()
				done := startWebMaster(t, m)
				// The launcher is registered inside the running hook. A dispatch
				// barrier after that hook has returned makes its Wait safe.
				if err := m.Do(t.Context(), func(context.Context) error { return nil }); err != nil {
					t.Fatal(err)
				}
				m.browser.Wait()
				stopWebMaster(t, m, done)
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				var data []byte
				select {
				case data = <-logs:
				case <-time.After(10 * time.Second):
					t.Fatal("browser log reader did not finish")
				}
				if !bytes.Contains(data, []byte("No web browser found. Please open a browser and point it to")) {
					t.Fatalf("missing headless message: %s", data)
				}
				if got := bytes.Contains(data, []byte("You can configure a fixed authentication token")); got != tt.hint {
					t.Fatalf("token hint=%t want=%t", got, tt.hint)
				}
				if tt.password != "" && strings.Contains(string(data), tt.password) {
					t.Fatal("plaintext password logged")
				}
			})
		}
	})
}
