// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package vtcodes

import "golang.org/x/sys/unix"

// ioctlReadTermios is the ioctl that reads the terminal attributes.
const ioctlReadTermios = unix.TCGETS
