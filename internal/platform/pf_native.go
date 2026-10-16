// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package platform

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/zchee/mitmproxy-go/connection"
)

type pfLayout struct {
	size, alignment                         int
	ioctl                                   uintptr
	source, destination, result             int
	sourcePort, destinationPort, resultPort int
	family, protocol, direction             int
}

type pfCalls struct {
	open             func() (int, error)
	ioctl            func(int, uintptr, []byte) error
	close            func(int) error
	family4, family6 byte
}

func pfNatLook(ctx context.Context, local, peer netip.AddrPort, layout pfLayout, calls pfCalls) (result connection.Address, err error) {
	if err := ctx.Err(); err != nil {
		return connection.Address{}, err
	}
	localIP, peerIP := local.Addr().Unmap(), peer.Addr().Unmap()
	if !localIP.IsValid() || !peerIP.IsValid() || localIP.Is4() != peerIP.Is4() || local.Port() == 0 || peer.Port() == 0 {
		return connection.Address{}, ErrInvalidAddress
	}
	buf := make([]byte, layout.size)
	family := calls.family6
	if peerIP.Is4() {
		family = calls.family4
	}
	copy(buf[layout.source:], peerIP.AsSlice())
	copy(buf[layout.destination:], localIP.AsSlice())
	binary.BigEndian.PutUint16(buf[layout.sourcePort:], peer.Port())
	binary.BigEndian.PutUint16(buf[layout.destinationPort:], local.Port())
	buf[layout.family], buf[layout.protocol], buf[layout.direction] = family, 6, 2 // IPPROTO_TCP, PF_OUT.
	fd, err := calls.open()
	if err != nil {
		return connection.Address{}, err
	}
	defer func() {
		if closeErr := calls.close(fd); closeErr != nil {
			result, err = connection.Address{}, errors.Join(err, closeErr)
		}
	}()
	if err := ctx.Err(); err != nil {
		return connection.Address{}, err
	}
	if err := calls.ioctl(fd, layout.ioctl, buf); err != nil {
		return connection.Address{}, err
	}
	if err := ctx.Err(); err != nil {
		return connection.Address{}, err
	}
	if buf[layout.family] != family || buf[layout.protocol] != 6 || buf[layout.direction] != 2 {
		return connection.Address{}, ErrInvalidAddress
	}
	var ip netip.Addr
	if peerIP.Is4() {
		ip = netip.AddrFrom4([4]byte(buf[layout.result : layout.result+4]))
	} else {
		ip = netip.AddrFrom16([16]byte(buf[layout.result : layout.result+16]))
	}
	return validatedAddress(connection.Address{Host: ip.Unmap().String(), Port: int(binary.BigEndian.Uint16(buf[layout.resultPort:]))})
}
