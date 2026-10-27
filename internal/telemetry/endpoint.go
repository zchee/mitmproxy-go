// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zchee/mitmproxy-go/options"
)

type endpoint struct {
	base url.URL
}

func parseEndpoint(value string) (endpoint, error) {
	invalid := &options.OptionsError{Msg: "otel_exporter_endpoint must be an HTTP(S) base URL without credentials, query or fragment; plaintext requires loopback"}
	if value == "" {
		return endpoint{}, nil
	}
	if len(value) > 4096 || strings.ContainsAny(value, "?#") {
		return endpoint{}, invalid
	}
	u, err := url.Parse(value)
	if err != nil || u.Opaque != "" || u.User != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return endpoint{}, invalid
	}
	if strings.HasSuffix(u.Host, ":") || strings.Contains(u.Hostname(), "%") {
		return endpoint{}, invalid
	}
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return endpoint{}, invalid
		}
	}
	if u.Scheme == "http" && u.Hostname() != "localhost" {
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || !ip.Unmap().IsLoopback() {
			return endpoint{}, invalid
		}
	}
	return endpoint{base: *u}, nil
}

func (e endpoint) signalURL(signal string) string {
	return e.base.JoinPath("v1", signal).String()
}

func newHTTPClient(listeners func() []netip.AddrPort, tlsConfig *tls.Config) (*http.Client, *http.Transport) {
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                  nil,
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    3 * time.Second,
		ResponseHeaderTimeout:  3 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           2,
		MaxIdleConnsPerHost:    2,
		MaxConnsPerHost:        2,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("telemetry: invalid collector address")
		}
		var ips []netip.Addr
		if host == "localhost" {
			ips = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		} else if ip, err := netip.ParseAddr(host); err == nil {
			ips = []netip.Addr{ip.Unmap()}
		} else {
			ips, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, errors.New("telemetry: collector resolution failed")
			}
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("telemetry: invalid collector address")
		}
		var own []netip.AddrPort
		if listeners != nil {
			own = listeners()
		}
		for _, ip := range ips {
			if selfListener(ip.Unmap(), uint16(n), own) {
				return nil, errors.New("telemetry: collector is a proxy or diagnostics listener")
			}
		}
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, errors.New("telemetry: collector connection failed")
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("telemetry: collector redirects are refused")
		},
	}
	return client, transport
}

func selfListener(ip netip.Addr, port uint16, listeners []netip.AddrPort) bool {
	for _, listener := range listeners {
		if listener.Port() != port {
			continue
		}
		if listener.Addr().Unmap() == ip {
			return true
		}
		if !listener.Addr().IsUnspecified() {
			continue
		}
		if ip.IsLoopback() {
			return true
		}
		addresses, err := net.InterfaceAddrs()
		if err != nil {
			// Without a local-address inventory a wildcard could be our own
			// listener. Refuse rather than risk recursively proxying export.
			return true
		}
		for _, address := range addresses {
			if prefix, err := netip.ParsePrefix(address.String()); err == nil && prefix.Addr().Unmap() == ip {
				return true
			}
		}
	}
	return false
}
