// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build unix

package script

import (
	"os"

	"golang.org/x/sys/unix"
)

func openSource(path string) (*os.File, error) {
	// A replaced path must not block in open if it became a FIFO between
	// stat and open. Regular-file reads are unaffected by O_NONBLOCK.
	return os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0) //nolint:gosec // The operator selects this source; readSource checks the opened object and bounds its bytes.
}
