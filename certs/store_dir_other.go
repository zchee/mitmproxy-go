// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !unix

package certs

func checkStoreDirectory(_ string) error {
	// Windows permissions are ACL-based, not POSIX modes and numeric UIDs.
	// Other non-Unix platforms also lack the ownership metadata checked here.
	return nil
}
