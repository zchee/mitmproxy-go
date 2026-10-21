// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !unix

package script

import "os"

func openSource(path string) (*os.File, error) {
	return os.Open(path) //nolint:gosec // The operator selects this source; readSource checks the opened object and bounds its bytes.
}
