// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
)

func packetSourceDestination(modeSpec string, conn interface{ LocalAddr() net.Addr }) (*connection.Address, error) {
	mode, err := modespec.Parse(modeSpec)
	if err != nil {
		// Handler callers may supply their own layer and mode labels.
		return nil, nil
	}
	switch mode.(type) {
	case modespec.WireGuardMode, modespec.TunMode, modespec.LocalMode:
	default:
		return nil, nil
	}
	if metadata, ok := conn.(interface{ GetExtraInfo(string) (any, bool) }); ok {
		if value, present := metadata.GetExtraInfo("remote_endpoint"); present {
			endpoint, ok := value.(string)
			if !ok {
				return nil, errors.New("packet source remote endpoint must be a string")
			}
			host, portText, err := net.SplitHostPort(endpoint)
			if err != nil {
				return nil, fmt.Errorf("invalid packet source remote endpoint: %w", err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil || host == "" || port < 1 || port > 65535 {
				return nil, errors.New("invalid packet source remote endpoint address")
			}
			return &connection.Address{Host: host, Port: port}, nil
		}
	}
	destination := addressOf(conn.LocalAddr())
	if destination == nil || destination.Host == "" || destination.Port < 1 || destination.Port > 65535 {
		return nil, errors.New("packet source has no destination address")
	}
	return destination, nil
}
