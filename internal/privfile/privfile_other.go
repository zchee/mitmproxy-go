// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !unix && !windows

package privfile

import (
	"errors"
	"os"
)

func openPrivate(path string, _ bool) (*os.File, error) {
	return nil, &os.PathError{Op: "open private output", Path: path, Err: errors.New("private output is unsupported on this platform")}
}
