// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build windows

package acceptance_test

import (
	"errors"
	"os"
)

func checkArtifactRootOwner(os.FileInfo) error {
	return errors.New("console artifact directory ownership cannot be verified on Windows")
}
