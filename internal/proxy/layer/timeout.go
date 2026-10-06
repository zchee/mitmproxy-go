// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layer

import "time"

const (
	// HeadReadTimeout bounds protocol head parsing independently of the idle
	// watchdog and tcp_timeout. The fixed deadline expires despite trickled
	// bytes; consumers inject their clock through the existing clock facility.
	HeadReadTimeout = 30 * time.Second
	// UDPIdleTimeout expires an inactive client/server tuple independently of
	// other tuples sharing the listener. Datagram activity resets this deadline.
	UDPIdleTimeout = 20 * time.Second
)
