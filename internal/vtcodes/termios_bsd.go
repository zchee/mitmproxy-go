// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package vtcodes

import "golang.org/x/sys/unix"

// ioctlReadTermios is the ioctl that reads the terminal attributes.
const ioctlReadTermios = unix.TIOCGETA
