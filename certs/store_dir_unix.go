// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build unix

package certs

import (
	"fmt"
	"os"
	"syscall"
)

func checkStoreDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("certs: configuration directory %s is not a directory; refusing to write the CA", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("certs: configuration directory %s is writable by other users (mode %s); refusing to write the CA", path, info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("certs: configuration directory %s is not owned by the current user; refusing to write the CA", path)
	}
	return nil
}
