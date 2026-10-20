// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func viewerOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Getuid())
}

func lockViewerFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

func renameViewerDirectory(parent *os.Root, from, to string) (published bool, err error) {
	file, err := parent.Open(".")
	if err != nil {
		return false, err
	}
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}()
	err = unix.Renameat2(int(file.Fd()), from, int(file.Fd()), to, unix.RENAME_NOREPLACE)
	return err == nil, err
}
