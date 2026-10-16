// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package processinfo lists running executables and retrieves their icons.
package processinfo

import (
	"cmp"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// Process describes one executable, which may have several running instances.
type Process struct {
	Executable  string
	DisplayName string
	IsVisible   bool
	IsSystem    bool
}

// UnsupportedError reports an operation unavailable on the current platform.
type UnsupportedError struct {
	Operation string
	Platform  string
}

// Error describes the unsupported operation.
func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("processinfo: %s is unsupported on %s", e.Operation, e.Platform)
}

type processRecord struct {
	pid         int32
	executable  string
	displayName string
	isSystem    bool
}

func groupProcesses(records []processRecord, visible map[int32]struct{}) []Process {
	records = slices.Clone(records)
	slices.SortFunc(records, func(a, b processRecord) int { return cmp.Compare(a.pid, b.pid) })
	indices := make(map[string]int, len(records))
	result := make([]Process, 0, len(records))
	for _, record := range records {
		if record.executable == "" {
			continue
		}
		_, isVisible := visible[record.pid]
		if index, found := indices[record.executable]; found {
			result[index].IsVisible = result[index].IsVisible || isVisible
			continue
		}
		name := record.displayName
		if name == "" {
			name = filepath.Base(record.executable)
		}
		indices[record.executable] = len(result)
		result = append(result, Process{
			Executable: record.executable, DisplayName: name,
			IsVisible: isVisible, IsSystem: record.isSystem,
		})
	}
	slices.SortFunc(result, func(a, b Process) int { return strings.Compare(a.Executable, b.Executable) })
	return result
}

func readWindowPIDs(count int64, pidAt func(int64) (int32, error)) (map[int32]struct{}, error) {
	if count < 0 {
		return nil, fmt.Errorf("processinfo: invalid window count %d", count)
	}
	pids := make(map[int32]struct{})
	for index := range count {
		pid, err := pidAt(index)
		if err != nil {
			return nil, err
		}
		if pid > 0 {
			pids[pid] = struct{}{}
		}
	}
	return pids, nil
}

func systemProcess(platform, executable string, uid int32, uidKnown bool) bool {
	switch platform {
	case "darwin":
		return strings.HasPrefix(executable, "/System/")
	case "linux":
		return uidKnown && uid >= 0 && uid < 1000
	default:
		return false
	}
}
