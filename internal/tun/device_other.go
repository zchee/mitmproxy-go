// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !linux

// Package tun configures Linux TUN devices and carries their IP packets.
package tun

import (
	"errors"
	"log/slog"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Open returns "TUN proxy mode is only supported on Linux" on this platform.
// On Linux it opens the named or automatically named TUN device and transfers
// device ownership to the caller, who must close it. A nil logger uses
// slog.Default on Linux.
func Open(_ string, _ *slog.Logger) (wgtun.Device, error) {
	return nil, errors.New("TUN proxy mode is only supported on Linux")
}
