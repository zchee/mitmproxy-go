// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build darwin || linux

package processinfo

import (
	"context"
	"fmt"
	"runtime"
)

// ActiveExecutables returns running executables, grouped by their exact paths.
// When instances differ, the lowest PID supplies nonvisibility metadata.
func ActiveExecutables() ([]Process, error) {
	visible, err := visibleProcessIDs()
	if err != nil {
		return nil, fmt.Errorf("processinfo: visible windows: %w", err)
	}
	processes, err := snapshotProcesses(context.Background())
	if err != nil {
		return nil, fmt.Errorf("processinfo: enumerate processes: %w", err)
	}
	records := make([]processRecord, 0, len(processes))
	for _, entry := range processes {
		records = append(records, processRecord{
			pid: entry.PID, executable: entry.Executable,
			isSystem: systemProcess(runtime.GOOS, entry.Executable, int64(entry.UID), entry.UIDKnown),
		})
	}
	return groupProcesses(records, visible), nil
}
