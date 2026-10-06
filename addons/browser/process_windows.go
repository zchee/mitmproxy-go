// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build windows

package browser

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

func killProcess(process *os.Process) error {
	var err error
	// Pin the original handle rather than reopening a possibly terminated PID.
	handleErr := process.WithHandle(func(handle uintptr) {
		status, waitErr := windows.WaitForSingleObject(windows.Handle(handle), 0)
		if waitErr == nil && status == windows.WAIT_OBJECT_0 {
			err = os.ErrProcessDone
			return
		}
		err = process.Kill()
		if err != nil {
			// The reaper or native exit may race Kill; only an exit signal proves
			// completion. An unsignaled process retains its termination error.
			status, waitErr = windows.WaitForSingleObject(windows.Handle(handle), 0)
			if waitErr == nil && status == windows.WAIT_OBJECT_0 {
				err = os.ErrProcessDone
			}
		}
	})
	if handleErr != nil {
		err = process.Kill()
		// Only cmd.Wait releases handles for children owned by this addon.
		if errors.Is(err, syscall.EINVAL) {
			return os.ErrProcessDone
		}
	}
	return err
}
