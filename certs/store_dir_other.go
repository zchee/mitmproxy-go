// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !unix

package certs

import "os"

func checkStoreDirectory(_ *os.Root) error {
	// Windows permissions are ACL-based, not POSIX modes and numeric UIDs.
	// Other non-Unix platforms also lack the ownership metadata checked here.
	return nil
}
