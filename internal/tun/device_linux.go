// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package tun configures Linux TUN devices and carries their IP packets.
package tun

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Open creates a Linux TUN device, or attaches to the named persistent device
// without reconfiguring it when configuration fails with EPERM. An empty name
// requests an automatically assigned interface name. A nil logger uses
// slog.Default. The caller owns the returned device and must close it. The device
// is ready for packet I/O immediately; its Events channel does not emit EventUp.
// On other platforms Open returns "TUN proxy mode is only supported on Linux".
func Open(name string, logger *slog.Logger) (wgtun.Device, error) {
	if logger == nil {
		logger = slog.Default()
	}
	fd, actual, configured, err := setupDevice(name, setupOps{
		open: func() (int, error) {
			return unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		},
		close:     unix.Close,
		attach:    attachInterface,
		configure: configureInterface,
	})
	if err != nil {
		//nolint:staticcheck // Preserve upstream's capitalized creation diagnostic.
		return nil, fmt.Errorf("Failed to create TUN device: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if configured {
		configureDevice("/proc/sys/net/ipv4/conf", actual, logger)
	}
	duplicate, err := duplicateDescriptor(fd)
	if err != nil {
		//nolint:staticcheck // Preserve upstream's capitalized creation diagnostic.
		return nil, fmt.Errorf("Failed to create TUN device: %w", err)
	}
	// The prechecked duplicate belongs to wireguard-go's os.File from this
	// call onward, including wrapper errors. Never close its descriptor number
	// here: the wrapper or its file finalizer owns that close.
	dev, _, err := wgtun.CreateUnmonitoredTUNFromFD(duplicate)
	if err != nil {
		//nolint:staticcheck // Preserve upstream's capitalized creation diagnostic.
		return nil, fmt.Errorf("Failed to create TUN device: %w", err)
	}
	return dev, nil
}
