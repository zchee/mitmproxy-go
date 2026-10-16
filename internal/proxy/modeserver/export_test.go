// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"net"
	"testing"

	"github.com/zchee/mitmproxy-go/connection"
)

// SetTransparentLookupForTest replaces only an instance's OS boundary and restores it after listeners stop.
func SetTransparentLookupForTest(t *testing.T, instance *Instance, check func(context.Context) error, lookup func(context.Context, *net.TCPConn) (connection.Address, error)) {
	t.Helper()
	previousCheck, previousLookup := instance.checkTransparent, instance.originalAddr
	instance.checkTransparent, instance.originalAddr = check, lookup
	t.Cleanup(func() {
		_ = instance.Stop()
		instance.checkTransparent, instance.originalAddr = previousCheck, previousLookup
	})
}
