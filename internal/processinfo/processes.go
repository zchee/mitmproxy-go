// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package processinfo exposes executable identity and presentation information.
package processinfo

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/shirou/gopsutil/v4/process"
)

// Process describes one executable, potentially shared by multiple processes.
type Process struct {
	Executable, DisplayName string
	IsVisible, IsSystem     bool
}

type processSnapshot struct {
	PID        int32
	Executable string
	UID        uint32
	UIDKnown   bool
}

func snapshotProcesses(ctx context.Context) ([]processSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	processes, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("enumerate processes: %w", err)
	}
	result := make([]processSnapshot, 0, len(processes))
	for _, item := range processes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		executable, err := item.ExeWithContext(ctx)
		if err != nil || executable == "" {
			continue
		}
		entry := processSnapshot{PID: item.Pid, Executable: executable}
		if ids, err := item.UidsWithContext(ctx); err == nil && len(ids) != 0 {
			entry.UID, entry.UIDKnown = ids[0], true
		}
		result = append(result, entry)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(result, func(a, b processSnapshot) int { return cmp.Compare(a.PID, b.PID) })
	return result, nil
}
