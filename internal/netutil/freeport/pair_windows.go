// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

var dynamicWindowsPorts = sync.OnceValue(func() pairDomain {
	var bounds [2]portRange
	for index, protocol := range []string{"tcp", "udp"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		output, err := exec.CommandContext(ctx, "netsh", "int", "ipv4", "show", "dynamicportrange", "protocol="+protocol).CombinedOutput() //nolint:gosec // Fixed command and protocol names, independent of caller input.
		cancel()
		if err == nil {
			bounds[index], err = parseDynamicPorts(string(output))
		}
		if err != nil {
			slog.Warn("Paired port domain unavailable; using randomized dynamic-range bind checks", "error", fmt.Errorf("read Windows %s dynamic port range: %w", protocol, err))
			return pairDomain{bounds: portRange{first: 49152, last: 65535}}
		}
	}
	return pairDomain{
		bounds:    portRange{first: max(bounds[0].first, bounds[1].first), last: min(bounds[0].last, bounds[1].last)},
		available: true,
	}
})

var pairPortDomain = newPairDiscovery(func() pairDomain {
	excluded := excludedWindowsPorts()
	domain := dynamicWindowsPorts()
	domain.excluded = append(append([]portRange(nil), excluded.tcp...), excluded.udp...)
	return domain
})

func collisionPairBind(err error) bool {
	// Winsock bind errors use their native codes, not Go's invented POSIX errno namespace.
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.Errno(10048))
}

func retryablePairBind(err error) bool {
	return collisionPairBind(err) || errors.Is(err, syscall.Errno(10013))
}
