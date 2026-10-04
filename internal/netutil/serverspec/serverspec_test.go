// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package serverspec

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// The first block of cases is mitmproxy's test_server_spec.py; the rest
// were checked against upstream's parse on CPython 3.14.
func TestParse(t *testing.T) {
	tests := map[string]struct {
		spec          string
		defaultScheme string
		wantScheme    string
		wantAddress   Address
	}{
		"success: default scheme and port": {
			spec: "example.com", defaultScheme: "https",
			wantScheme: "https", wantAddress: Address{Host: "example.com", Port: 443},
		},
		"success: explicit scheme wins": {
			spec: "http://example.com", defaultScheme: "https",
			wantScheme: "http", wantAddress: Address{Host: "example.com", Port: 80},
		},
		"success: explicit port": {
			spec: "smtp.example.com:25", defaultScheme: "tcp",
			wantScheme: "tcp", wantAddress: Address{Host: "smtp.example.com", Port: 25},
		},
		"success: IPv4": {
			spec: "http://127.0.0.1", defaultScheme: "https",
			wantScheme: "http", wantAddress: Address{Host: "127.0.0.1", Port: 80},
		},
		"success: bracketed IPv6": {
			spec: "http://[::1]", defaultScheme: "https",
			wantScheme: "http", wantAddress: Address{Host: "::1", Port: 80},
		},
		"success: bracketed IPv6 with trailing slash": {
			spec: "http://[::1]/", defaultScheme: "https",
			wantScheme: "http", wantAddress: Address{Host: "::1", Port: 80},
		},
		"success: https IPv6": {
			spec: "https://[::1]/", defaultScheme: "https",
			wantScheme: "https", wantAddress: Address{Host: "::1", Port: 443},
		},
		"success: IPv6 with port": {
			spec: "http://[::1]:8080", defaultScheme: "https",
			wantScheme: "http", wantAddress: Address{Host: "::1", Port: 8080},
		},
		"success: leading zeros in port": {
			spec: "example.com:0080", defaultScheme: "tcp",
			wantScheme: "tcp", wantAddress: Address{Host: "example.com", Port: 80},
		},
		"success: IPv6 with port and default scheme": {
			spec: "[::1]:443", defaultScheme: "tcp",
			wantScheme: "tcp", wantAddress: Address{Host: "::1", Port: 443},
		},
		"success: dns defaults to 53": {
			spec: "[::1]", defaultScheme: "dns",
			wantScheme: "dns", wantAddress: Address{Host: "::1", Port: 53},
		},
		"success: quic defaults to 443": {
			spec: "example.com/", defaultScheme: "quic",
			wantScheme: "quic", wantAddress: Address{Host: "example.com", Port: 443},
		},
		"success: http3 defaults to 443": {
			spec: "http3://example.com", defaultScheme: "tcp",
			wantScheme: "http3", wantAddress: Address{Host: "example.com", Port: 443},
		},
		"success: bracketed name": {
			spec: "[example.com]", defaultScheme: "http",
			wantScheme: "http", wantAddress: Address{Host: "example.com", Port: 80},
		},
		"success: bracketed IPv4 with port": {
			spec: "[1.2.3.4]:5", defaultScheme: "tcp",
			wantScheme: "tcp", wantAddress: Address{Host: "1.2.3.4", Port: 5},
		},
		"success: explicit udp scheme": {
			spec: "udp://1.2.3.4:53", defaultScheme: "http",
			wantScheme: "udp", wantAddress: Address{Host: "1.2.3.4", Port: 53},
		},
		"success: invalid default scheme is unused": {
			spec: "dns://8.8.8.8", defaultScheme: "x",
			wantScheme: "dns", wantAddress: Address{Host: "8.8.8.8", Port: 53},
		},
		"success: IDN host": {
			spec: "münchen.de", defaultScheme: "https",
			wantScheme: "https", wantAddress: Address{Host: "münchen.de", Port: 443},
		},
		"success: IPv6 with port and trailing slash": {
			spec: "[::1]:8080/", defaultScheme: "https",
			wantScheme: "https", wantAddress: Address{Host: "::1", Port: 8080},
		},
		"success: port zero": {
			spec: "tls://example.com:0", defaultScheme: "https",
			wantScheme: "tls", wantAddress: Address{Host: "example.com", Port: 0},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			scheme, address, err := Parse(tt.spec, tt.defaultScheme)
			if err != nil {
				t.Fatalf("Parse(%q, %q) error: %v", tt.spec, tt.defaultScheme, err)
			}
			if scheme != tt.wantScheme {
				t.Errorf("Parse(%q, %q) scheme = %q, want %q", tt.spec, tt.defaultScheme, scheme, tt.wantScheme)
			}
			if diff := cmp.Diff(tt.wantAddress, address); diff != "" {
				t.Errorf("Parse(%q, %q) address mismatch (-want +got):\n%s", tt.spec, tt.defaultScheme, diff)
			}
		})
	}
}

func TestParseError(t *testing.T) {
	tests := map[string]struct {
		spec          string
		defaultScheme string
		want          Error
		wantMessage   string
	}{
		"error: colon only": {
			spec: ":", defaultScheme: "https",
			want: Error{Reason: InvalidSpecification, Value: ":"}, wantMessage: "Invalid server specification: :",
		},
		"error: unknown scheme": {
			spec: "ftp://example.com", defaultScheme: "https",
			want: Error{Reason: InvalidScheme, Value: "ftp"}, wantMessage: "Invalid server scheme: ftp",
		},
		"error: invalid hostname": {
			spec: "$$$", defaultScheme: "https",
			want: Error{Reason: InvalidHostname, Value: "$$$"}, wantMessage: "Invalid hostname: $$$",
		},
		"error: port out of range": {
			spec: "example.com:999999", defaultScheme: "https",
			want: Error{Reason: InvalidPort, Value: "999999"}, wantMessage: "Invalid port: 999999",
		},
		"error: no default port for tcp": {
			spec: "example.com", defaultScheme: "tcp",
			want: Error{Reason: MissingPort}, wantMessage: "Port specification missing.",
		},
		"error: double trailing slash": {
			spec: "example.com//", defaultScheme: "http",
			want: Error{Reason: InvalidSpecification, Value: "example.com//"}, wantMessage: "Invalid server specification: example.com//",
		},
		"error: path": {
			spec: "http://example.com/path", defaultScheme: "http",
			want: Error{Reason: InvalidSpecification, Value: "http://example.com/path"}, wantMessage: "Invalid server specification: http://example.com/path",
		},
		"error: schemes are case-sensitive": {
			spec: "HTTP://example.com", defaultScheme: "http",
			want: Error{Reason: InvalidScheme, Value: "HTTP"}, wantMessage: "Invalid server scheme: HTTP",
		},
		"error: empty port": {
			spec: "example.com:", defaultScheme: "http",
			want: Error{Reason: InvalidSpecification, Value: "example.com:"}, wantMessage: "Invalid server specification: example.com:",
		},
		"error: port 65536": {
			spec: "1.2.3.4:65536", defaultScheme: "tcp",
			want: Error{Reason: InvalidPort, Value: "65536"}, wantMessage: "Invalid port: 65536",
		},
		"error: no default port for udp": {
			spec: "example.com", defaultScheme: "udp",
			want: Error{Reason: MissingPort}, wantMessage: "Port specification missing.",
		},
		"error: empty spec": {
			spec: "", defaultScheme: "http",
			want: Error{Reason: InvalidSpecification, Value: ""}, wantMessage: "Invalid server specification: ",
		},
		"error: invalid default scheme": {
			spec: "example.com", defaultScheme: "ftp",
			want: Error{Reason: InvalidScheme, Value: "ftp"}, wantMessage: "Invalid server scheme: ftp",
		},
		"error: space in hostname": {
			spec: "a b", defaultScheme: "http",
			want: Error{Reason: InvalidHostname, Value: "a b"}, wantMessage: "Invalid hostname: a b",
		},
		"error: port overflowing int": {
			spec: "x:99999999999999999999999", defaultScheme: "tcp",
			want: Error{Reason: InvalidPort, Value: "99999999999999999999999"}, wantMessage: "Invalid port: 99999999999999999999999",
		},
		"error: port with leading zeros out of range": {
			spec: "x:0065536", defaultScheme: "tcp",
			want: Error{Reason: InvalidPort, Value: "65536"}, wantMessage: "Invalid port: 65536",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			scheme, address, err := Parse(tt.spec, tt.defaultScheme)
			if err == nil {
				t.Fatalf("Parse(%q, %q) = %q, %+v, want error", tt.spec, tt.defaultScheme, scheme, address)
			}
			e, ok := errors.AsType[*Error](err)
			if !ok {
				t.Fatalf("Parse(%q, %q) error %T is not *Error", tt.spec, tt.defaultScheme, err)
			}
			if diff := cmp.Diff(tt.want, *e); diff != "" {
				t.Errorf("Parse(%q, %q) error mismatch (-want +got):\n%s", tt.spec, tt.defaultScheme, diff)
			}
			if got := err.Error(); got != tt.wantMessage {
				t.Errorf("Parse(%q, %q) message = %q, want %q", tt.spec, tt.defaultScheme, got, tt.wantMessage)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{"example.com", "http://[::1]:8080/", "tcp://1.2.3.4:53", ":", "$$$"} {
		f.Add(seed, "https")
	}
	f.Fuzz(func(t *testing.T, spec, defaultScheme string) {
		scheme, address, err := Parse(spec, defaultScheme)
		if err != nil {
			if _, ok := errors.AsType[*Error](err); !ok {
				t.Fatalf("Parse(%q, %q) error %T is not *Error", spec, defaultScheme, err)
			}
			return
		}
		if _, ok := schemes[scheme]; !ok {
			t.Errorf("Parse(%q, %q) returned unknown scheme %q", spec, defaultScheme, scheme)
		}
		if address.Port < 0 || address.Port > 65535 {
			t.Errorf("Parse(%q, %q) returned port %d", spec, defaultScheme, address.Port)
		}
	})
}
