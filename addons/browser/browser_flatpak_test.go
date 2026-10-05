// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package browser

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
)

// TestFlatpak ports test_find_flatpak_cmd and test_find_flatpak_cmd_no_flatpak.
// A held info subprocess proves that commands and other dispatch work complete
// before a probe exits, without making a wall-clock performance assertion.
func TestFlatpak(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	binary := buildRecorder(t)
	tests := map[string]struct {
		name   string
		ids    []string
		absent bool
	}{
		"chrome first":  {"chrome", []string{"com.google.Chrome"}, false},
		"chrome last":   {"chrome", []string{"com.google.Chrome", "org.chromium.Chromium", "com.github.Eloston.UngoogledChromium", "com.google.ChromeDev"}, false},
		"chrome absent": {"chrome", []string{"com.google.Chrome", "org.chromium.Chromium", "com.github.Eloston.UngoogledChromium", "com.google.ChromeDev"}, true},
		"edge":          {"edge", []string{"com.microsoft.Edge"}, false},
		"firefox":       {"firefox", []string{"org.mozilla.firefox"}, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			browser, manager, listener, logs := setupBrowser(t, binary, "flatpak")
			if _, err := manager.Call(t.Context(), "browser.start", tt.name); err != nil {
				t.Fatal(err)
			}
			for i, id := range tt.ids {
				conn, record := acceptRecord(t, listener)
				if diff := gocmp.Diff([]string{"info", id}, record.Args); diff != "" {
					t.Fatal(diff)
				}
				// The subprocess cannot exit until this test replies, so reaching
				// this dispatch callback demonstrates the probe holds no lock.
				if err := manager.Do(t.Context(), func(context.Context) error {
					if len(browser.browser) != 0 {
						t.Fatal("browser launched before probe completed")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				status := "1"
				if i == len(tt.ids)-1 && !tt.absent {
					status = "0"
				}
				if _, err := io.WriteString(conn, status); err != nil {
					t.Fatal(err)
				}
			}
			if tt.absent {
				record := nextLog(t, logs)
				if record.Message != "Your platform is not supported yet - please submit a patch." || record.Level != addon.LevelAlert {
					t.Fatal(record)
				}
				return
			}
			_, record := acceptRecord(t, listener)
			want := []string{"run", "-p", tt.ids[len(tt.ids)-1]}
			if len(record.Args) < 3 {
				t.Fatalf("flatpak launch: %q", record.Args)
			}
			if diff := gocmp.Diff(want, record.Args[:3]); diff != "" {
				t.Fatal(diff)
			}
			if tt.name == "firefox" {
				if len(record.Args) != 7 || record.Args[3] != "--profile" || record.Prefs == "" {
					t.Fatal(record)
				}
			} else {
				if len(record.Args) != 10 || record.Args[4] != "--proxy-server=127.0.0.1:8080" {
					t.Fatal(record)
				}
			}
		})
	}
}

func TestDoneDuringProbe(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	binary := buildRecorder(t)
	browser, manager, listener, logs := setupBrowser(t, binary, "flatpak")
	if _, err := manager.Call(t.Context(), "browser.start"); err != nil {
		t.Fatal(err)
	}
	conn, _ := acceptRecord(t, listener)
	if err := manager.Trigger(t.Context(), addon.DoneHook{}); err != nil {
		t.Fatal(err)
	}
	waitWorkers(t, browser)
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		hang(t, "pending probe was not terminated")
	}
	if len(browser.browser) != 0 {
		t.Fatal("launch survived done")
	}
	select {
	case record := <-logs:
		t.Fatalf("cancellation logged as launch failure: %v", record)
	default:
	}
	// A later start has a new lifetime and does not inherit cancellation.
	if _, err := manager.Call(t.Context(), "browser.start", "edge"); err != nil {
		t.Fatal(err)
	}
	probe, _ := acceptRecord(t, listener)
	if _, err := io.WriteString(probe, "0"); err != nil {
		t.Fatal(err)
	}
	_, record := acceptRecord(t, listener)
	if record.Args[2] != "com.microsoft.Edge" {
		t.Fatal(record.Args)
	}
}

// The candidate lookup is the sole substitution seam: the process itself is
// still started through os/exec, which reports a real missing-file failure.
func TestStartFailure(t *testing.T) {
	binary := buildRecorder(t)
	browser, manager, _, _ := setupBrowser(t, binary, "chrome")
	profiles := t.TempDir()
	t.Setenv("TMPDIR", profiles)
	t.Setenv("TMP", profiles)
	lookup := browser.lookPath
	browser.lookPath = func(name string) (string, error) {
		path, err := lookup(name)
		if err == nil {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		return path, err
	}
	if _, err := manager.Call(t.Context(), "browser.start"); err == nil {
		t.Fatal("missing process succeeded")
	}
	if len(browser.browser) != 0 {
		t.Fatal("failed start retained a child")
	}
	entries, err := os.ReadDir(profiles)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed start retained profiles: %v", entries)
	}
}

func TestExitedBrowserCleanup(t *testing.T) {
	binary := buildRecorder(t)
	browser, manager, listener, _ := setupBrowser(t, binary, "chrome")
	if _, err := manager.Call(t.Context(), "browser.start"); err != nil {
		t.Fatal(err)
	}
	conn, _ := acceptRecord(t, listener)
	if _, err := io.WriteString(conn, "0"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		hang(t, "child did not exit")
	}
	var child browserProcess
	if err := manager.Do(t.Context(), func(ctx context.Context) error {
		child = browser.browser[0]
		return browser.Done(ctx)
	}); err != nil {
		t.Fatal(err)
	}
	waitWorkers(t, browser)
	if child.cmd.ProcessState == nil {
		t.Fatal("exited child not reaped")
	}
	if _, err := os.Stat(child.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("profile still exists: %v", err)
	}
}
