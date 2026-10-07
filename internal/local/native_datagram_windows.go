// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"errors"
	"net"
)

func connectNativeDatagram(_ *net.UnixConn, _ string) error {
	return errors.New("linux redirector Unix datagrams are unsupported on Windows")
}

func nativeDatagramTruncated(_ int) bool { return true }
