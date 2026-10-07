// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package wireguard connects encrypted WireGuard tunnels to userspace packet devices.
package wireguard

import (
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// newDevice transfers ownership of tunDevice and bind to the returned engine.
// Close stops the workers and closes both resources; it may be called repeatedly.
func newDevice(tunDevice tun.Device, bind conn.Bind, logger *device.Logger) *device.Device {
	return device.NewDevice(tunDevice, bind, logger)
}
