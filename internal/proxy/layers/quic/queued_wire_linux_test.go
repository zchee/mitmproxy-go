// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build linux

package quic

import (
	"encoding/binary"
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func queuedSegmentSize(oob []byte) (int, error) {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, err
	}
	for _, message := range messages {
		if message.Header.Level == unix.SOL_UDP && message.Header.Type == unix.UDP_SEGMENT {
			if len(message.Data) != 2 {
				return 0, errors.New("queued QUIC fixture: malformed UDP segment control")
			}
			size := binary.NativeEndian.Uint16(message.Data)
			if size == 0 {
				return 0, errors.New("queued QUIC fixture: zero UDP segment size")
			}
			return int(size), nil
		}
	}
	return 0, nil
}

func writeQueuedSegments(p *queuedQUICConn, data []byte, segment int, addr *net.UDPAddr) (int, error) {
	oob := make([]byte, unix.CmsgSpace(2))
	header := unix.Cmsghdr{Level: unix.SOL_UDP, Type: unix.UDP_SEGMENT}
	header.SetLen(unix.CmsgLen(2))
	// Marshal the native header through the same public ancillary-data layout
	// quic-go uses, without exposing or reading the control socket descriptor.
	if _, err := binary.Encode(oob, binary.NativeEndian, header); err != nil {
		return 0, err
	}
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], uint16(segment))
	n, _, err := p.WriteMsgUDP(data, oob, addr)
	return n, err
}
