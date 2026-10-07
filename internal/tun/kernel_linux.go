// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tun

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func attachInterface(fd int, name string) (string, error) {
	request, err := unix.NewIfreq(name)
	if err != nil {
		return "", err
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		return "", err
	}
	return request.Name(), nil
}

func configureInterface(name string) error {
	request, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	request.SetUint32(65535)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFMTU, request); err != nil {
		return fmt.Errorf("set TUN MTU: %w", err)
	}
	if err := request.SetInet4Addr([]byte{169, 254, 0, 1}); err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFADDR, request); err != nil {
		return fmt.Errorf("set TUN address: %w", err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, request); err != nil {
		return fmt.Errorf("get TUN flags: %w", err)
	}
	request.SetUint16(request.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, request); err != nil {
		return fmt.Errorf("bring TUN interface up: %w", err)
	}
	return nil
}
