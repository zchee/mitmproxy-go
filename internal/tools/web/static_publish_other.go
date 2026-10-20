// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !darwin && !linux

package web

import (
	"errors"
	"os"
)

func viewerOwned(os.FileInfo) bool { return false }

func lockViewerFile(*os.File) error {
	return errors.New("static viewer atomic non-replacing publication is unsupported on this platform")
}

func renameViewerDirectory(*os.Root, string, string) (bool, error) {
	return false, errors.New("static viewer atomic non-replacing publication is unsupported on this platform")
}
