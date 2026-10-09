// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"sync"
	"time"
)

type windowsPortRanges struct {
	tcp []portRange
	udp []portRange
	err error
}

var excludedWindowsPorts = sync.OnceValue(func() windowsPortRanges {
	var ranges windowsPortRanges
	for _, protocol := range []string{"tcp", "udp"} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		output, err := exec.CommandContext(ctx, "netsh", "int", "ipv4", "show", "excludedportrange", "protocol="+protocol).CombinedOutput() //nolint:gosec // The command and protocol names are fixed; no caller input reaches netsh.
		cancel()
		if err == nil {
			var parsed []portRange
			parsed, err = parseExcludedPorts(string(output))
			if protocol == "tcp" {
				ranges.tcp = parsed
			} else {
				ranges.udp = parsed
			}
		}
		if err != nil {
			err = fmt.Errorf("read Windows %s excluded port ranges: %w", protocol, err)
			slog.Warn("Excluded port ranges unavailable; using socket bind checks", "error", err)
			return windowsPortRanges{err: err}
		}
	}
	return ranges
})

func isExcludedPort(port int, paired bool) bool {
	ranges := excludedWindowsPorts()
	return inPortRanges(port, ranges.tcp) || paired && inPortRanges(port, ranges.udp)
}
