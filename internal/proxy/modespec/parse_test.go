// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modespec

import (
	"reflect"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/netutil/serverspec"
)

func TestParseAsTypes(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		spec  string
		parse func(string) (Mode, error)
		zero  Mode
	}{
		"regular":     {"regular", parseAsMode[RegularMode], RegularMode{}},
		"transparent": {"transparent", parseAsMode[TransparentMode], TransparentMode{}},
		"upstream":    {"upstream:proxy", parseAsMode[UpstreamMode], UpstreamMode{}},
		"reverse":     {"reverse:host", parseAsMode[ReverseMode], ReverseMode{}},
		"socks5":      {"socks5", parseAsMode[Socks5Mode], Socks5Mode{}},
		"dns":         {"dns", parseAsMode[DNSMode], DNSMode{}},
		"wireguard":   {"wireguard", parseAsMode[WireGuardMode], WireGuardMode{}},
		"local":       {"local", parseAsMode[LocalMode], LocalMode{}},
		"tun":         {"tun", parseAsMode[TunMode], TunMode{}},
		"interface":   {"regular", parseAsMode[Mode], RegularMode{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mode, err := tt.parse(tt.spec)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.TypeOf(mode) != reflect.TypeOf(tt.zero) {
				t.Fatalf("ParseAs(%q) returned %T; want %T", tt.spec, mode, tt.zero)
			}
			if mode.Name() != tt.zero.Name() || mode.String() != tt.spec {
				t.Errorf("ParseAs(%q) returned name %q and spec %q", tt.spec, mode.Name(), mode.String())
			}
		})
	}
}

func parseAsMode[M Mode](spec string) (Mode, error) {
	return ParseAs[M](spec)
}

// Embedding a mode promotes its methods, but does not register a new mode.
type unregisteredMode struct{ RegularMode }

func TestParseAsUnsupportedTypes(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		parse func(string) (Mode, error)
		want  string
	}{
		"pointer":       {parseAsMode[*RegularMode], "ParseAs requires a concrete mode value type or Mode"},
		"embedded mode": {parseAsMode[unregisteredMode], "unsupported mode type: modespec.unregisteredMode"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := tt.parse("regular")
			if err == nil || err.Error() != tt.want {
				t.Errorf("unsupported ParseAs error = %v; want %q", err, tt.want)
			}
		})
	}
}

func TestReverseSchemes(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		transport  TransportProtocol
		listenPort int
	}{
		"http":  {TCP, 8080},
		"https": {Both, 8080},
		"http3": {UDP, 8080},
		"tls":   {TCP, 8080},
		"dtls":  {UDP, 8080},
		"tcp":   {TCP, 8080},
		"udp":   {UDP, 8080},
		"dns":   {Both, 53},
		"quic":  {UDP, 8080},
	}
	for scheme, tt := range tests {
		t.Run(scheme, func(t *testing.T) {
			t.Parallel()
			mode, err := ParseAs[ReverseMode]("reverse:" + scheme + "://[::1]:443")
			if err != nil {
				t.Fatal(err)
			}
			if mode.Scheme != scheme || mode.TransportProtocol() != tt.transport {
				t.Errorf("scheme/transport = %s/%s; want %s/%s", mode.Scheme, mode.TransportProtocol(), scheme, tt.transport)
			}
			if diff := gocmp.Diff(serverspec.Address{Host: "::1", Port: 443}, mode.Address); diff != "" {
				t.Errorf("target address (-want +got):\n%s", diff)
			}
			if port, ok := mode.DefaultPort(); !ok || port != tt.listenPort {
				t.Errorf("DefaultPort() = %d, %v; want %d, true", port, ok, tt.listenPort)
			}
		})
	}
}
