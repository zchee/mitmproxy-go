// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !linux

package quic

import "net"

// quic-go only supplies UDP segmentation control messages on Linux.
func queuedSegmentSize([]byte) (int, error) { return 0, nil }

func writeQueuedSegments(p *queuedQUICConn, data []byte, segment int, addr *net.UDPAddr) (int, error) {
	return p.writeSegments(data, segment, addr)
}
