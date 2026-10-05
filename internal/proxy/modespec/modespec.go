// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package modespec parses mitmproxy mode specifications of the form
// mode[:configuration][@[listen_host:]listen_port]. Parsing accepts all modes;
// the server decides which modes it supports.
package modespec

import "github.com/zchee/mitmproxy-go/internal/netutil/serverspec"

// TransportProtocol identifies the transports a mode's listener serves.
type TransportProtocol string

const (
	// TCP selects a TCP listener.
	TCP TransportProtocol = "tcp"
	// UDP selects a UDP listener.
	UDP TransportProtocol = "udp"
	// Both selects TCP and UDP listeners.
	Both TransportProtocol = "both"
)

// Mode is a parsed proxy mode. Parse returns comparable value types, not
// pointers. Treat them as immutable after sharing them with other goroutines.
// The unexported method reserves implementations to this package.
type Mode interface {
	// Name is the lowercase mode name.
	Name() string
	// Description is the mode's display name for logs and user interfaces.
	Description() string
	// DefaultPort returns the mode's port and whether it has one.
	DefaultPort() (int, bool)
	// TransportProtocol returns the transports served by this mode.
	TransportProtocol() TransportProtocol
	// ListenHost uses the explicit host, then the supplied default.
	ListenHost(defaultHost string) string
	// ListenPort uses the explicit port, then defaultPort if non-nil, then
	// DefaultPort. The bool is false for modes without a listening port.
	ListenPort(defaultPort *int) (int, bool)
	// Common returns a copy of the original specification and listen overrides.
	Common() Spec
	// String returns the full specification exactly as supplied to Parse.
	String() string
	isMode()
}

// Spec holds the fields shared by all modes. Presence flags distinguish an
// absent host or port from an explicit empty host or port zero, without
// pointers that would change value equality. CustomListenHost is kept verbatim,
// including IPv6 brackets; the listener removes brackets when binding.
type Spec struct {
	// FullSpec is the complete input to Parse.
	FullSpec string
	// Data is the raw configuration after the mode name.
	Data string
	// CustomListenHost is the explicitly supplied listen host.
	CustomListenHost string
	// HasCustomListenHost reports whether CustomListenHost was specified.
	HasCustomListenHost bool
	// CustomListenPort is the explicitly supplied listen port.
	CustomListenPort int
	// HasCustomListenPort reports whether CustomListenPort was specified.
	HasCustomListenPort bool
}

// ListenHost returns the explicit host, or defaultHost if absent.
func (s Spec) ListenHost(defaultHost string) string {
	if s.HasCustomListenHost {
		return s.CustomListenHost
	}
	return defaultHost
}

// Common returns a copy of the fields shared by all modes.
func (s Spec) Common() Spec { return s }

// String returns the original specification.
func (s Spec) String() string { return s.FullSpec }

func (Spec) isMode() {}

func (s Spec) listenPort(defaultPort *int, modePort int, hasModePort bool) (int, bool) {
	if s.HasCustomListenPort {
		return s.CustomListenPort, true
	}
	if defaultPort != nil {
		return *defaultPort, true
	}
	return modePort, hasModePort
}

// RegularMode is an explicit HTTP(S) proxy supporting CONNECT.
type RegularMode struct{ Spec }

// Name returns the mode name.
func (RegularMode) Name() string { return "regular" }

// Description returns the display name.
func (RegularMode) Description() string { return "HTTP(S) proxy" }

// DefaultPort returns 8080.
func (RegularMode) DefaultPort() (int, bool) { return 8080, true }

// TransportProtocol returns TCP.
func (RegularMode) TransportProtocol() TransportProtocol { return TCP }

// ListenPort resolves the explicit, configured and mode defaults in that order.
func (m RegularMode) ListenPort(defaultPort *int) (int, bool) {
	return m.listenPort(defaultPort, 8080, true)
}

// TransparentMode intercepts connections redirected by the operating system.
type TransparentMode struct{ Spec }

// Name returns the mode name.
func (TransparentMode) Name() string { return "transparent" }

// Description returns the display name.
func (TransparentMode) Description() string { return "Transparent Proxy" }

// DefaultPort returns 8080.
func (TransparentMode) DefaultPort() (int, bool) { return 8080, true }

// TransportProtocol returns TCP.
func (TransparentMode) TransportProtocol() TransportProtocol { return TCP }

// ListenPort resolves the explicit, configured and mode defaults in that order.
func (m TransparentMode) ListenPort(defaultPort *int) (int, bool) {
	return m.listenPort(defaultPort, 8080, true)
}

// UpstreamMode forwards HTTP(S) through another HTTP(S) proxy.
type UpstreamMode struct {
	Spec
	// Scheme is http or https.
	Scheme string
	// Address is the upstream proxy's host and port.
	Address serverspec.Address
}

// Name returns the mode name.
func (UpstreamMode) Name() string { return "upstream" }

// Description returns the display name.
func (UpstreamMode) Description() string { return "HTTP(S) proxy (upstream mode)" }

// DefaultPort returns 8080.
func (UpstreamMode) DefaultPort() (int, bool) { return 8080, true }

// TransportProtocol returns TCP.
func (UpstreamMode) TransportProtocol() TransportProtocol { return TCP }

// ListenPort resolves the explicit, configured and mode defaults in that order.
func (m UpstreamMode) ListenPort(defaultPort *int) (int, bool) {
	return m.listenPort(defaultPort, 8080, true)
}

// ReverseMode forwards connections to a fixed server.
type ReverseMode struct {
	Spec
	// Scheme is the server protocol accepted by serverspec.Parse.
	Scheme string
	// Address is the destination server's host and port.
	Address serverspec.Address
}

// Name returns the mode name.
func (ReverseMode) Name() string { return "reverse" }

// Description returns the display name and original destination text.
func (m ReverseMode) Description() string { return "reverse proxy to " + m.Data }

// DefaultPort returns 53 for DNS and 8080 for all other protocols.
func (m ReverseMode) DefaultPort() (int, bool) {
	if m.Scheme == "dns" {
		return 53, true
	}
	return 8080, true
}

// TransportProtocol returns UDP for http3, dtls, udp and quic, Both for dns
// and https, and TCP for the remaining schemes.
func (m ReverseMode) TransportProtocol() TransportProtocol {
	switch m.Scheme {
	case "http3", "dtls", "udp", "quic":
		return UDP
	case "dns", "https":
		return Both
	default:
		return TCP
	}
}

// ListenPort resolves the explicit, configured and mode defaults in that order.
func (m ReverseMode) ListenPort(defaultPort *int) (int, bool) {
	port, ok := m.DefaultPort()
	return m.listenPort(defaultPort, port, ok)
}

// Socks5Mode is a SOCKSv5 proxy.
type Socks5Mode struct{ Spec }

// Name returns the mode name.
func (Socks5Mode) Name() string { return "socks5" }

// Description returns the display name.
func (Socks5Mode) Description() string { return "SOCKS v5 proxy" }

// DefaultPort returns 1080.
func (Socks5Mode) DefaultPort() (int, bool) { return 1080, true }

// TransportProtocol returns TCP.
func (Socks5Mode) TransportProtocol() TransportProtocol { return TCP }

// ListenPort resolves the explicit, configured and mode defaults in that order.
func (m Socks5Mode) ListenPort(defaultPort *int) (int, bool) {
	return m.listenPort(defaultPort, 1080, true)
}

// DNSMode is a DNS server over TCP and UDP.
type DNSMode struct{ Spec }

// Name returns the mode name.
func (DNSMode) Name() string { return "dns" }

// Description returns the display name.
func (DNSMode) Description() string { return "DNS server" }

// DefaultPort returns 53.
func (DNSMode) DefaultPort() (int, bool) { return 53, true }

// TransportProtocol returns Both.
func (DNSMode) TransportProtocol() TransportProtocol { return Both }

// ListenPort resolves the explicit, configured and mode defaults in that order.
func (m DNSMode) ListenPort(defaultPort *int) (int, bool) {
	return m.listenPort(defaultPort, 53, true)
}

// WireGuardMode is a WireGuard server. Data is its optional configuration path.
type WireGuardMode struct{ Spec }

// Name returns the mode name.
func (WireGuardMode) Name() string { return "wireguard" }

// Description returns the display name.
func (WireGuardMode) Description() string { return "WireGuard server" }

// DefaultPort returns 51820.
func (WireGuardMode) DefaultPort() (int, bool) { return 51820, true }

// TransportProtocol returns UDP.
func (WireGuardMode) TransportProtocol() TransportProtocol { return UDP }

// ListenPort resolves the explicit, configured and mode defaults in that order.
func (m WireGuardMode) ListenPort(defaultPort *int) (int, bool) {
	return m.listenPort(defaultPort, 51820, true)
}

// LocalMode redirects local processes. Data is its intercept specification.
type LocalMode struct{ Spec }

// Name returns the mode name.
func (LocalMode) Name() string { return "local" }

// Description returns the display name.
func (LocalMode) Description() string { return "Local redirector" }

// DefaultPort reports that local redirection has no listening port.
func (LocalMode) DefaultPort() (int, bool) { return 0, false }

// TransportProtocol returns Both.
func (LocalMode) TransportProtocol() TransportProtocol { return Both }

// ListenPort resolves the explicit or configured port, if either is supplied.
func (m LocalMode) ListenPort(defaultPort *int) (int, bool) {
	return m.listenPort(defaultPort, 0, false)
}

// TunMode redirects through a TUN interface. Data is its optional name.
type TunMode struct{ Spec }

// Name returns the mode name.
func (TunMode) Name() string { return "tun" }

// Description returns the display name.
func (TunMode) Description() string { return "TUN interface" }

// DefaultPort reports that a TUN interface has no listening port.
func (TunMode) DefaultPort() (int, bool) { return 0, false }

// TransportProtocol returns Both.
func (TunMode) TransportProtocol() TransportProtocol { return Both }

// ListenPort resolves the explicit or configured port, if either is supplied.
func (m TunMode) ListenPort(defaultPort *int) (int, bool) {
	return m.listenPort(defaultPort, 0, false)
}
