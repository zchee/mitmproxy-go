// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build windows

package modeserver

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isAddrInUse(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE)
}

// Windows may exclude a UDP port that its ephemeral TCP allocator selected.
// This classification is used only to acquire a new shared-port candidate.
func isSharedUDPBindRetryable(err error) bool {
	return isAddrInUse(err) || errors.Is(err, windows.WSAEACCES)
}
