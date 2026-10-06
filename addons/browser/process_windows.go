// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build windows

package browser

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func killProcess(process *os.Process) error {
	// Hold the original process object across Kill and the nonblocking exit check.
	handle, handleErr := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(process.Pid))
	if handleErr == nil {
		defer func() { _ = windows.CloseHandle(handle) }()
	}
	err := process.Kill()
	if handleErr == nil && errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		// TerminateProcess reports access denied for an already-exited child.
		// An unsignaled process still exposes its genuine termination failure.
		status, waitErr := windows.WaitForSingleObject(handle, 0)
		if waitErr == nil && status == windows.WAIT_OBJECT_0 {
			return os.ErrProcessDone
		}
	}
	return err
}
