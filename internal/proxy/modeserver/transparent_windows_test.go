// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/platform"
)

func TestTransparentWindowsRefusal(t *testing.T) {
	cfg, _, _ := fixture(t)
	instance := makeInstance(t, "transparent@127.0.0.1:0", cfg)
	instance.listenTCP = func(context.Context, string, string) (net.Listener, error) {
		t.Fatal("Windows refusal opened a listener")
		return nil, platform.ErrWindowsRefusal
	}
	const want = "Transparent mode on Windows is unsupported, flaky, and deprecated. Consider using local redirect mode or WireGuard mode instead."
	err := instance.Start(t.Context())
	if err == nil || err.Error() != want || !errors.Is(err, platform.ErrWindowsRefusal) || !errors.Is(err, platform.ErrUnsupported) {
		t.Fatalf("Windows refusal = %v, want exact diagnostic and typed causes", err)
	}
	if instance.IsRunning() || len(instance.ListenAddrs()) != 0 || instance.LastError() != err {
		t.Fatal("Windows refusal published a listener or lost its error")
	}
}
