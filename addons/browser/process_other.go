// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !windows

package browser

import "os"

func killProcess(process *os.Process) error {
	return process.Kill()
}
