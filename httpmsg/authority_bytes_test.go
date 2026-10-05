// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestParseAuthorityBytes(t *testing.T) {
	tests := map[string]struct {
		input   string
		host    string
		port    int
		invalid bool
	}{
		"success: Latin IDNA label":                             {input: "xn--aaa-pla.example:80", host: "äaaa.example", port: 80},
		"success: Japanese IDNA labels":                         {input: "xn--r8jz45g.xn--zckzah:80", host: "例え.テスト", port: 80},
		"success: preserve decoded case":                        {input: "XN--AAA-PLA.example:80", host: "äAAA.example", port: 80},
		"success: preserve ASCII case":                          {input: "Example.COM:80", host: "Example.COM", port: 80},
		"success: absent port":                                  {input: "xn--bcher-kva.test", host: "bücher.test", port: -1},
		"success: IPv6 brackets":                                {input: "[2001:db8::1]:443", host: "2001:db8::1", port: 443},
		"error: empty IDNA label":                               {input: "xn--:80", invalid: true},
		"error: prohibited decoded characters":                  {input: "xn--abc:80", invalid: true},
		"error: noncanonical IDNA label":                        {input: "xn--not-punycode-:80", invalid: true},
		"error: invalid UTF-8":                                  {input: "\xff:80", invalid: true},
		"error: unencoded Unicode host":                         {input: "bücher.test:80", invalid: true},
		"error: invalid port preserves original IDNA authority": {input: "xn--bcher-kva.test:999999999", invalid: true},
		"error: empty inner label":                              {input: "foo..bar:80", invalid: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for _, strict := range []bool{false, true} {
				host, port, err := ParseAuthorityBytes([]byte(tt.input), strict)
				if tt.invalid && strict {
					if err == nil {
						t.Fatal("malformed wire authority accepted in strict mode")
					}
					continue
				}
				if err != nil {
					t.Fatalf("strict=%t: %v", strict, err)
				}
				wantHost, wantPort := tt.host, tt.port
				if tt.invalid {
					wantHost, wantPort = tt.input, -1
				}
				if diff := gocmp.Diff(wantHost, host); diff != "" {
					t.Errorf("strict=%t host (-want +got):\n%s", strict, diff)
				}
				if port != wantPort {
					t.Errorf("strict=%t port=%d, want %d", strict, port, wantPort)
				}
			}
		})
	}
}
