// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build ignore

package processinfo

import (
	"errors"
	"fmt"
	"strings"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/windows"
)

// ActiveExecutables returns running executables, grouped by their exact paths.
func ActiveExecutables() ([]Process, error) {
	visible, err := visibleProcessIDs()
	if err != nil {
		return nil, err
	}
	pids, err := process.Pids()
	if err != nil {
		return nil, fmt.Errorf("processinfo: enumerate processes: %w", err)
	}
	records := make([]processRecord, 0, len(pids))
	for _, pid := range pids {
		path, critical, err := windowsProcessDetails(pid)
		if err != nil {
			if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
				continue
			}
			return nil, err
		}
		_, basename, _ := strings.CutLast(path, `\`)
		if basename == "" {
			basename = path
		}
		records = append(records, processRecord{pid: pid, executable: path, displayName: basename, isSystem: critical})
	}
	result := groupProcesses(records, visible)
	for index := range result {
		if result[index].IsVisible {
			if name, err := windowsDisplayName(result[index].Executable); err == nil {
				result[index].DisplayName = name
			}
		}
	}
	return result, nil
}
