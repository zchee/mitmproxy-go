// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package debugserver

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/zchee/mitmproxy-go/options"
)

func parseAddress(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	invalid := &options.OptionsError{Msg: "pprof_addr must be a literal loopback host:port (or localhost) with a numeric port in 0..65535"}
	host, port, err := net.SplitHostPort(value)
	if err != nil || port == "" {
		return "", invalid
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", invalid
	}
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" || !address.Unmap().IsLoopback() {
		return "", invalid
	}
	return net.JoinHostPort(address.Unmap().String(), strconv.FormatUint(number, 10)), nil
}
