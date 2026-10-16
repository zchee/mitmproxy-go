// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build ignore

package processinfo

import (
	"fmt"
	"runtime"

	"github.com/shirou/gopsutil/v4/process"
)

// ActiveExecutables returns running executables, grouped by their exact paths.
func ActiveExecutables() ([]Process, error) {
	visible, err := visibleProcessIDs()
	if err != nil {
		return nil, fmt.Errorf("processinfo: visible windows: %w", err)
	}
	processes, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("processinfo: enumerate processes: %w", err)
	}
	records := make([]processRecord, 0, len(processes))
	for _, entry := range processes {
		executable, err := entry.Exe()
		if err != nil || executable == "" {
			continue
		}
		var uid int32
		var uidKnown bool
		if runtime.GOOS == "linux" {
			uids, err := entry.Uids()
			if err == nil && len(uids) != 0 {
				uid, uidKnown = int32(uids[0]), true
			}
		}
		records = append(records, processRecord{
			pid: entry.Pid, executable: executable,
			isSystem: systemProcess(runtime.GOOS, executable, uid, uidKnown),
		})
	}
	return groupProcesses(records, visible), nil
}
