// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modespec

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/netutil/serverspec"
)

// Upstream test/mitmproxy/proxy/test_mode_specs.py coverage:
// test_parse -> TestParse, TestParseErrors, TestModeValues.
// test_parse_subclass -> TestParseAs.
// test_listen_addr -> TestListenAddress.
// test_parse_specific_modes -> TestSpecificModes, TestParseErrors.
// Python repr and set_state/FrozenInstanceError have no Go counterpart:
// String returns the saved spec, Parse restores it, and modes are copied values.
// The commented-out http3 mode is not registered upstream either.

func TestParseErrors(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		spec string
		want string
	}{
		"unknown mode":       {"flibbel", "unknown mode"},
		"empty mode":         {"", "unknown mode"},
		"unregistered http3": {"http3", "unknown mode"},
		"leading at sign":    {"@8080", "unknown mode"},
		"Unicode dotted I does not lowercase to ASCII":     {"WİREGUARD", "unknown mode"},
		"invalid listen port":                              {"regular@invalid-port", "invalid port: invalid-port"},
		"port checked before mode":                         {"flibbel@bad", "invalid port: bad"},
		"oversized port":                                   {"regular@99999", "invalid port: 99999"},
		"negative port":                                    {"regular@-1", "invalid port: -1"},
		"empty port":                                       {"regular@host:", "invalid port: "},
		"empty IPv6 port":                                  {"regular@[::1]:", "invalid port: "},
		"port prefix underscore":                           {"regular@_80", "invalid port: _80"},
		"port suffix underscore":                           {"regular@80_", "invalid port: 80_"},
		"port doubled underscore":                          {"regular@8__0", "invalid port: 8__0"},
		"hexadecimal port":                                 {"regular@0x50", "invalid port: 0x50"},
		"fractional port":                                  {"regular@80.0", "invalid port: 80.0"},
		"sign without digits":                              {"regular@+", "invalid port: +"},
		"ASCII record separator is not integer whitespace": {"regular@\x1c80", "invalid port: \x1c80"},
		"integer digit limit":                              {"regular@" + strings.Repeat("0", 4301), "invalid port: " + strings.Repeat("0", 4301)},
		"regular takes no data":                            {"regular:configuration", "mode takes no arguments"},
		"transparent takes no data":                        {"transparent:configuration", "mode takes no arguments"},
		"socks takes no data":                              {"socks5:configuration", "mode takes no arguments"},
		"dns takes no data":                                {"dns:invalid", "mode takes no arguments"},
		"upstream rejects dns scheme":                      {"upstream:dns://example.com", "invalid upstream proxy scheme"},
		"missing reverse port":                             {"reverse:dtls://127.0.0.1", "Port specification missing."},
		"missing reverse target":                           {"reverse", "Invalid server specification: "},
		"invalid reverse scheme":                           {"reverse:ftp://example.com", "Invalid server scheme: ftp"},
		"invalid reverse target port":                      {"reverse:tcp://example.com:65536", "Invalid port: 65536"},
		"empty local patterns":                             {"local:,,,", "invalid intercept spec: ,,,"},
		"empty local exclusion":                            {"local: ! ", "invalid intercept spec:  ! "},
		"trailing local separator":                         {"local:firefox,", "invalid intercept spec: firefox,"},
		"renamed osproxy":                                  {"osproxy", "osproxy mode has been renamed to local mode. Thanks for trying our experimental features!"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mode, err := Parse(tt.spec)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("Parse(%q) = %v, %v; want nil, %q", tt.spec, mode, err, tt.want)
			}
			if mode != nil {
				t.Errorf("failed parse returned mode %v", mode)
			}
			if tt.want == "unknown mode" && !errors.Is(err, ErrUnknownMode) {
				t.Errorf("error %v does not match ErrUnknownMode", err)
			}
		})
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		spec string
		want Spec
	}{
		"reverse state round trip": {
			"reverse:https://example.com/@127.0.0.1:443",
			Spec{FullSpec: "reverse:https://example.com/@127.0.0.1:443", Data: "https://example.com/", CustomListenHost: "127.0.0.1", HasCustomListenHost: true, CustomListenPort: 443, HasCustomListenPort: true},
		},
		"IPv6 brackets preserved":               {"regular@[::1]:0", Spec{FullSpec: "regular@[::1]:0", CustomListenHost: "[::1]", HasCustomListenHost: true, HasCustomListenPort: true}},
		"explicit empty host":                   {"regular@:80", Spec{FullSpec: "regular@:80", HasCustomListenHost: true, CustomListenPort: 80, HasCustomListenPort: true}},
		"port only":                             {"regular@65535", Spec{FullSpec: "regular@65535", CustomListenPort: 65535, HasCustomListenPort: true}},
		"empty suffix":                          {"regular@", Spec{FullSpec: "regular@"}},
		"case insensitive name":                 {"ReGuLaR", Spec{FullSpec: "ReGuLaR"}},
		"empty data":                            {"regular:", Spec{FullSpec: "regular:"}},
		"last at sign separates listen address": {"wireguard:a@b@80", Spec{FullSpec: "wireguard:a@b@80", Data: "a@b", CustomListenPort: 80, HasCustomListenPort: true}},
		"Unicode port digits":                   {"regular@٠８𝟘", Spec{FullSpec: "regular@٠８𝟘", CustomListenPort: 80, HasCustomListenPort: true}},
		"signed separated port":                 {"regular@ +8_0\t", Spec{FullSpec: "regular@ +8_0\t", CustomListenPort: 80, HasCustomListenPort: true}},
		"Unicode port whitespace":               {"regular@ 80　", Spec{FullSpec: "regular@ 80　", CustomListenPort: 80, HasCustomListenPort: true}},
		"negative zero":                         {"regular@-0", Spec{FullSpec: "regular@-0", HasCustomListenPort: true}},
		"unvalidated listen host":               {"regular@not a hostname:80", Spec{FullSpec: "regular@not a hostname:80", CustomListenHost: "not a hostname", HasCustomListenHost: true, CustomListenPort: 80, HasCustomListenPort: true}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mode, err := Parse(tt.spec)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, mode.Common()); diff != "" {
				t.Errorf("parsed fields (-want +got):\n%s", diff)
			}
			if mode.String() != tt.spec {
				t.Errorf("String() = %q, want %q", mode.String(), tt.spec)
			}
			restored, err := Parse(mode.String())
			if err != nil || restored != mode {
				t.Errorf("Parse(String()) = %v, %v; want %v", restored, err, mode)
			}
		})
	}
}

func TestSpecificModes(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		spec        string
		mode        Mode
		name        string
		description string
		port        int
		hasPort     bool
		transport   TransportProtocol
	}{
		"regular":                 {"regular", RegularMode{FullSpec: "regular"}, "regular", "HTTP(S) proxy", 8080, true, TCP},
		"transparent":             {"transparent", TransparentMode{FullSpec: "transparent"}, "transparent", "Transparent Proxy", 8080, true, TCP},
		"upstream":                {"upstream:https://proxy", UpstreamMode{FullSpec: "upstream:https://proxy", Data: "https://proxy", Scheme: "https", Address: serverspec.Address{Host: "proxy", Port: 443}}, "upstream", "HTTP(S) proxy (upstream mode)", 8080, true, TCP},
		"upstream default":        {"upstream:proxy", UpstreamMode{FullSpec: "upstream:proxy", Data: "proxy", Scheme: "http", Address: serverspec.Address{Host: "proxy", Port: 80}}, "upstream", "HTTP(S) proxy (upstream mode)", 8080, true, TCP},
		"reverse HTTPS":           {"reverse:https://host@443", ReverseMode{FullSpec: "reverse:https://host@443", Data: "https://host", CustomListenPort: 443, HasCustomListenPort: true, Scheme: "https", Address: serverspec.Address{Host: "host", Port: 443}}, "reverse", "reverse proxy to https://host", 8080, true, Both},
		"reverse default":         {"reverse:host", ReverseMode{FullSpec: "reverse:host", Data: "host", Scheme: "https", Address: serverspec.Address{Host: "host", Port: 443}}, "reverse", "reverse proxy to host", 8080, true, Both},
		"reverse HTTP3":           {"reverse:http3://host@443", ReverseMode{FullSpec: "reverse:http3://host@443", Data: "http3://host", CustomListenPort: 443, HasCustomListenPort: true, Scheme: "http3", Address: serverspec.Address{Host: "host", Port: 443}}, "reverse", "reverse proxy to http3://host", 8080, true, UDP},
		"reverse DNS":             {"reverse:dns://8.8.8.8", ReverseMode{FullSpec: "reverse:dns://8.8.8.8", Data: "dns://8.8.8.8", Scheme: "dns", Address: serverspec.Address{Host: "8.8.8.8", Port: 53}}, "reverse", "reverse proxy to dns://8.8.8.8", 53, true, Both},
		"reverse DTLS":            {"reverse:dtls://127.0.0.1:8004", ReverseMode{FullSpec: "reverse:dtls://127.0.0.1:8004", Data: "dtls://127.0.0.1:8004", Scheme: "dtls", Address: serverspec.Address{Host: "127.0.0.1", Port: 8004}}, "reverse", "reverse proxy to dtls://127.0.0.1:8004", 8080, true, UDP},
		"socks5":                  {"socks5", Socks5Mode{FullSpec: "socks5"}, "socks5", "SOCKS v5 proxy", 1080, true, TCP},
		"dns":                     {"dns", DNSMode{FullSpec: "dns"}, "dns", "DNS server", 53, true, Both},
		"wireguard":               {"wireguard", WireGuardMode{FullSpec: "wireguard"}, "wireguard", "WireGuard server", 51820, true, UDP},
		"wireguard configuration": {"wireguard:foo.conf", WireGuardMode{FullSpec: "wireguard:foo.conf", Data: "foo.conf"}, "wireguard", "WireGuard server", 51820, true, UDP},
		"wireguard port":          {"wireguard@51821", WireGuardMode{FullSpec: "wireguard@51821", CustomListenPort: 51821, HasCustomListenPort: true}, "wireguard", "WireGuard server", 51820, true, UDP},
		"local":                   {"local", LocalMode{FullSpec: "local"}, "local", "Local redirector", 0, false, Both},
		"local patterns":          {"local:firefox, ! 123,!!", LocalMode{FullSpec: "local:firefox, ! 123,!!", Data: "firefox, ! 123,!!"}, "local", "Local redirector", 0, false, Both},
		"tun":                     {"tun", TunMode{FullSpec: "tun"}, "tun", "TUN interface", 0, false, Both},
		"tun name":                {"tun:utun42", TunMode{FullSpec: "tun:utun42", Data: "utun42"}, "tun", "TUN interface", 0, false, Both},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mode, err := Parse(tt.spec)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.mode, mode); diff != "" {
				t.Errorf("mode (-want +got):\n%s", diff)
			}
			if mode.Name() != tt.name || mode.Description() != tt.description || mode.TransportProtocol() != tt.transport {
				t.Errorf("metadata = %q, %q, %q; want %q, %q, %q", mode.Name(), mode.Description(), mode.TransportProtocol(), tt.name, tt.description, tt.transport)
			}
			if port, ok := mode.DefaultPort(); port != tt.port || ok != tt.hasPort {
				t.Errorf("DefaultPort() = %d, %v; want %d, %v", port, ok, tt.port, tt.hasPort)
			}
			if port, ok := mode.ListenPort(nil); !mode.Common().HasCustomListenPort && (port != tt.port || ok != tt.hasPort) {
				t.Errorf("ListenPort(nil) = %d, %v; want default %d, %v", port, ok, tt.port, tt.hasPort)
			}
		})
	}
}

func TestParseAs(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		spec string
		want string
	}{
		"valid":                            {"socks5", ""},
		"wrong mode":                       {"regular", "'regular' is not a spec for a socks5 mode"},
		"case preserved in error":          {"REGULAR", "'REGULAR' is not a spec for a socks5 mode"},
		"type checked before data":         {"regular:invalid", "'regular' is not a spec for a socks5 mode"},
		"type checked before target":       {"reverse:invalid://host", "'reverse' is not a spec for a socks5 mode"},
		"type checked before renamed mode": {"osproxy", "'osproxy' is not a spec for a socks5 mode"},
		"port checked before type":         {"regular@bad", "invalid port: bad"},
		"unknown type":                     {"flibbel", "unknown mode"},
		"own data checked":                 {"socks5:invalid", "mode takes no arguments"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mode, err := ParseAs[Socks5Mode](tt.spec)
			if tt.want != "" {
				if err == nil || err.Error() != tt.want {
					t.Fatalf("ParseAs(%q) = %v, %v; want %q", tt.spec, mode, err, tt.want)
				}
				if mode != (Socks5Mode{}) {
					t.Errorf("failed ParseAs returned nonzero mode %v", mode)
				}
			} else if err != nil || mode.FullSpec != tt.spec {
				t.Errorf("ParseAs(%q) = %v, %v", tt.spec, mode, err)
			}
		})
	}
}

func TestListenAddress(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		spec        string
		defaultHost string
		defaultPort *int
		host        string
		port        int
		hasPort     bool
	}{
		"defaults":                               {"regular", "", nil, "", 8080, true},
		"specified port":                         {"regular@1234", "", nil, "", 1234, true},
		"fallback port":                          {"regular", "", new(4424), "", 4424, true},
		"specified overrides fallback port":      {"regular@1234", "", new(4424), "", 1234, true},
		"no local port":                          {"local", "", nil, "", 0, false},
		"no tun port":                            {"tun", "", nil, "", 0, false},
		"local fallback port":                    {"local", "", new(0), "", 0, true},
		"specified local port":                   {"local@0", "", nil, "", 0, true},
		"specified host":                         {"regular@127.0.0.2:8080", "", nil, "127.0.0.2", 8080, true},
		"fallback host":                          {"regular", "127.0.0.3", nil, "127.0.0.3", 8080, true},
		"specified overrides fallback host":      {"regular@127.0.0.2:8080", "127.0.0.3", nil, "127.0.0.2", 8080, true},
		"explicit empty host overrides fallback": {"regular@:8080", "127.0.0.3", nil, "", 8080, true},
		"reverse HTTPS default":                  {"reverse:https://1.2.3.4", "", nil, "", 8080, true},
		"reverse DNS default":                    {"reverse:dns://8.8.8.8", "", nil, "", 53, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mode, err := Parse(tt.spec)
			if err != nil {
				t.Fatal(err)
			}
			if host := mode.ListenHost(tt.defaultHost); host != tt.host {
				t.Errorf("ListenHost(%q) = %q, want %q", tt.defaultHost, host, tt.host)
			}
			if port, ok := mode.ListenPort(tt.defaultPort); port != tt.port || ok != tt.hasPort {
				t.Errorf("ListenPort(%v) = %d, %v; want %d, %v", tt.defaultPort, port, ok, tt.port, tt.hasPort)
			}
		})
	}
}

func TestTunNames(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		name        string
		validDarwin bool
	}{
		"automatic":          {"", true},
		"ordinary":           {"utun42", true},
		"Unicode digits":     {"utun４٢", true},
		"final newline":      {"utun3\n", true},
		"two final newlines": {"utun3\n\n", false},
		"Linux name":         {"tun0", false},
		"missing number":     {"utun", false},
		"negative number":    {"utun-1", false},
		"fractional number":  {"utun1.5", false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mode, err := Parse("tun:" + tt.name)
			if runtime.GOOS == "darwin" && !tt.validDarwin {
				want := "Invalid tun name: " + tt.name + ". On macOS, the tun name must be the form utunx where x is a number, such as utun3."
				if err == nil || err.Error() != want {
					t.Fatalf("Parse(tun:%q) = %v, %v; want %q", tt.name, mode, err, want)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestModeValues(t *testing.T) {
	t.Parallel()
	original, err := ParseAs[RegularMode]("regular@80")
	if err != nil {
		t.Fatal(err)
	}
	copied := original
	copied.CustomListenPort = 443
	if original.CustomListenPort != 80 {
		t.Fatal("changing a copy changed the original mode")
	}
	common := original.Common()
	common.CustomListenPort = 443
	if common == original.Common() || original.Common().CustomListenPort != 80 {
		t.Fatal("changing Common() changed the original mode")
	}
	seen := map[Mode]bool{original: true}
	if seen[copied] || !seen[original] {
		t.Fatal("mode values do not compare by their fields")
	}
}
