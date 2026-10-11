// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// parentPairAdapter retains the resolver's release-at-selection-end algorithm.
// Its injected retry predicate models Windows bind exclusions on every host;
// the production resolver's equivalent predicate is GOOS-dependent.
func parentPairAdapter(listenTCP func() (net.Listener, error), listenUDP func(*net.UDPAddr) (*net.UDPConn, error), retryable func(error) bool) (net.Listener, *net.UDPConn, error) {
	var rejected []net.Listener
	defer func() {
		for _, listener := range rejected {
			_ = listener.Close()
		}
	}()
	var lastErr error
	for range 64 {
		tcp, err := listenTCP()
		if err != nil {
			return nil, nil, err
		}
		udp, err := listenUDP(net.UDPAddrFromAddrPort(tcp.Addr().(*net.TCPAddr).AddrPort()))
		if err == nil {
			return tcp, udp, nil
		}
		rejected = append(rejected, tcp)
		if !retryable(err) {
			return nil, nil, err
		}
		lastErr = err
	}
	return nil, nil, fmt.Errorf("DNS fixture shared bind exhausted %d candidates: %w", 64, lastErr)
}

func windowsPairBindFixture(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.Errno(10013)) || errors.Is(err, syscall.Errno(10048))
}

type pairedPortListener struct {
	net.Listener
	address *net.TCPAddr
	closes  *int
}

func (listener *pairedPortListener) Addr() net.Addr { return listener.address }

func (listener *pairedPortListener) Close() error {
	*listener.closes++
	if listener.Listener != nil {
		return listener.Listener.Close()
	}
	return nil
}
