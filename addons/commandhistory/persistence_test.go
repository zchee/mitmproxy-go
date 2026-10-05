// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package commandhistory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
)

func TestDefaultRetention(t *testing.T) {
	dir := t.TempDir()
	_, m, cmds, _ := setup(t, dir)
	var all []string
	for i := range 1023 {
		text := fmt.Sprintf("command-%d", i)
		all = append(all, text)
		call(t, cmds, "add", text)
	}
	if err := m.Trigger(t.Context(), addon.DoneHook{}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "command_history")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(nativeText(strings.Join(all, "\n")+"\n"), string(data)); diff != "" {
		t.Fatal(diff)
	}
	all = append(all, "command-1023")
	call(t, cmds, "add", "command-1023")
	if err := m.Trigger(t.Context(), addon.DoneHook{}); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(nativeText(strings.Join(all[512:], "\n")+"\n"), string(data)); diff != "" {
		t.Fatal(diff)
	}
	history(t, cmds, all)
}

func TestHistoryPath(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	} else {
		t.Setenv("HOME", dir)
	}
	tests := map[string]struct{ dir, want string }{
		"home":         {"~", filepath.Join(dir, "command_history")},
		"home child":   {"~" + string(filepath.Separator) + "history", filepath.Join(dir, "history", "command_history")},
		"unknown user": {"~mitmproxy-no-such-user-10923478", filepath.Join("~mitmproxy-no-such-user-10923478", "command_history")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, m, _, _ := setup(t, tt.dir)
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				if diff := cmp.Diff(tt.want, a.historyFile(ctx)); diff != "" {
					t.Fatal(diff)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReloadRetainsHistoryOnFailure(t *testing.T) {
	dir := t.TempDir()
	a, m, cmds, _ := setup(t, dir)
	call(t, cmds, "add", "retained")
	path := filepath.Join(dir, "command_history")
	if err := os.WriteFile(path, []byte{0xff}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.InvokeSync(t.Context(), a, addon.RunningHook{}); err == nil {
		t.Fatal("invalid text accepted")
	}
	history(t, cmds, []string{"retained"})
	if got := call(t, cmds, "prev"); got != "retained" {
		t.Fatalf("cursor=%v", got)
	}
}

func TestReadHistoryBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history")
	text := strings.Repeat("x", maxHistoryBytes)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readHistory(path)
	if err != nil || len(data) != maxHistoryBytes {
		t.Fatalf("boundary: len=%d err=%v", len(data), err)
	}
	if _, err := readHistory(path + "-missing"); err == nil {
		t.Fatal("missing file accepted")
	}
}
