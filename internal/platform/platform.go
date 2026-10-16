// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package platform recovers the destination of an accepted redirected TCP connection.
package platform

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"

	"github.com/zchee/mitmproxy-go/connection"
)

// Lookup failure causes, preserved through wrapping.
var (
	ErrUnsupported    = errors.New("transparent mode is unsupported on this platform")
	ErrWindowsRefusal = errors.New(windowsRefusal) //nolint:staticcheck // Preserve the upstream warning verbatim.
	ErrInvalidAddress = errors.New("invalid original destination address")
	ErrNotFound       = errors.New("Could not resolve original destination.")                                                                              //nolint:staticcheck // Preserve the upstream diagnostic verbatim.
	ErrPrivileges     = errors.New("Insufficient privileges to access pfctl. See https://mitmproxy.org/docs/latest/howto-transparent/#macos for details.") //nolint:staticcheck // Preserve the upstream diagnostic verbatim.
	ErrPFOutput       = errors.New("invalid or incomplete pfctl state output")
)

const windowsRefusal = "Transparent mode on Windows is unsupported, flaky, and deprecated. Consider using local redirect mode or WireGuard mode instead."

// CheckTransparent checks cancellation and OS support before a mode creates listeners.
// PF privilege and ABI checks require an accepted connection and occur in OriginalAddr.
func CheckTransparent(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return checkOS(runtime.GOOS)
}

func checkOS(os string) error {
	switch os {
	case "linux", "darwin", "freebsd", "openbsd":
		return nil
	case "windows":
		// Upstream logs this warning but still attempts legacy WinDivert setup.
		// This port deliberately refuses that deprecated implementation.
		return windowsError{}
	default:
		return fmt.Errorf("%s: %w", os, ErrUnsupported)
	}
}

type windowsError struct{}

func (windowsError) Error() string   { return windowsRefusal }
func (windowsError) Unwrap() []error { return []error{ErrUnsupported, ErrWindowsRefusal} }

// OriginalAddr returns the pre-redirection destination without taking ownership of conn.
// Errors preserve cancellation, platform, address, privilege and native syscall causes.
func OriginalAddr(ctx context.Context, conn *net.TCPConn) (connection.Address, error) {
	if err := CheckTransparent(ctx); err != nil {
		return connection.Address{}, err
	}
	if conn == nil {
		return connection.Address{}, fmt.Errorf("nil TCP connection: %w", ErrInvalidAddress)
	}
	a, err := originalAddr(ctx, conn)
	if err != nil {
		return connection.Address{}, err
	}
	if err := ctx.Err(); err != nil {
		return connection.Address{}, err
	}
	return validatedAddress(a)
}

func validatedAddress(a connection.Address) (connection.Address, error) {
	ip, err := netip.ParseAddr(a.Host)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() || a.Port < 1 || a.Port > 65535 {
		return connection.Address{}, ErrInvalidAddress
	}
	a.Host = ip.Unmap().String()
	return a, nil
}

func tcpAddress(a net.Addr) (netip.AddrPort, error) {
	tcp, ok := a.(*net.TCPAddr)
	if !ok || tcp == nil || tcp.Port < 1 || tcp.Port > 65535 {
		return netip.AddrPort{}, ErrInvalidAddress
	}
	ip, ok := netip.AddrFromSlice(tcp.IP)
	if !ok || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.AddrPort{}, ErrInvalidAddress
	}
	ip = ip.Unmap()
	if tcp.Zone != "" && ip.Is6() {
		ip = ip.WithZone(tcp.Zone)
	}
	return netip.AddrPortFrom(ip, uint16(tcp.Port)), nil
}

func decodeSockaddr(b []byte, ipv4 bool) (connection.Address, error) {
	want, family := 28, uint16(10) // Linux sockaddr_in6.
	if ipv4 {
		want, family = 16, 2
	}
	if len(b) != want || binary.NativeEndian.Uint16(b[:2]) != family {
		return connection.Address{}, ErrInvalidAddress
	}
	port := int(binary.BigEndian.Uint16(b[2:4]))
	var ip netip.Addr
	if ipv4 {
		ip = netip.AddrFrom4([4]byte(b[4:8]))
	} else {
		ip = netip.AddrFrom16([16]byte(b[8:24]))
	}
	a := connection.Address{Host: ip.Unmap().String(), Port: port}
	if !ipv4 {
		flow := binary.BigEndian.Uint32(b[4:8])
		scope := binary.NativeEndian.Uint32(b[24:28])
		if flow != 0 || scope != 0 {
			a.Scope = &connection.IPv6Scope{FlowInfo: flow, ScopeID: scope}
		}
	}
	return validatedAddress(a)
}
