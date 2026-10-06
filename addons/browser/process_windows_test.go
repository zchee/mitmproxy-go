// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build windows

package browser

import (
	"errors"
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/zchee/mitmproxy-go/options"
)

func TestDoneAfterProcessExit(t *testing.T) {
	tests := map[string]struct{ reaped bool }{
		"success: native exit before reaping": {},
		"success: native exit after reaping":  {reaped: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), "cmd.exe", "/c", "exit", "0")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			})
			handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = windows.CloseHandle(handle) }()
			// Observe native exit without letting os.Process.Wait mark it reaped.
			status, err := windows.WaitForSingleObject(handle, 30_000)
			if err != nil || status != windows.WAIT_OBJECT_0 {
				hang(t, "child process did not exit")
			}
			if tt.reaped {
				if err := cmd.Wait(); err != nil {
					t.Fatal(err)
				}
			} else if err := cmd.Process.Kill(); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				t.Fatalf("Kill of exited, unreaped child = %v, want access denied", err)
			}
			browser := New(options.New(), nil)
			browser.browser = []browserProcess{{cmd: cmd}}
			if err := browser.Done(t.Context()); err != nil {
				t.Fatalf("Done of exited child = %v", err)
			}
			if !tt.reaped {
				if err := cmd.Wait(); err != nil {
					t.Fatal(err)
				}
			}
			if err := browser.Done(t.Context()); err != nil {
				t.Fatalf("repeated Done = %v", err)
			}
		})
	}
}
