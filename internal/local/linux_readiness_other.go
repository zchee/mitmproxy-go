// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !linux

package local

import (
	"context"
	"errors"
	"net"
)

func waitLinuxInterceptDrain(context.Context, *net.UnixConn, <-chan struct{}) error {
	return errors.ErrUnsupported
}
