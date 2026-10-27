// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package debugserver

import (
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/options"
)

func TestDebugAddress(t *testing.T) {
	t.Run("addresses", func(t *testing.T) {
		tests := map[string]struct {
			input string
			want  string
			bad   []string
		}{
			"empty":            {input: "", want: ""},
			"ipv4_loopback":    {input: "127.12.34.56:6060", want: "127.12.34.56:6060"},
			"ipv6_loopback":    {input: "[::1]:6060", want: "[::1]:6060"},
			"mapped_loopback":  {input: "[::ffff:127.0.0.1]:00080", want: "127.0.0.1:80"},
			"localhost_fixed":  {input: "LOCALHOST:0", want: "127.0.0.1:0"},
			"wildcard_refused": {bad: []string{"0.0.0.0:6060", "[::]:6060", ":6060", "[::ffff:0.0.0.0]:6060"}},
			"remote_refused":   {bad: []string{"192.0.2.1:6060", "[2001:db8::1]:6060", "[::ffff:192.0.2.1]:6060"}},
			"hostname_refused": {bad: []string{"example.com:6060", "localhost.example:6060", "localhost.:6060", "127.0.0.1.example:6060"}},
			"zone_refused":     {bad: []string{"[::1%lo0]:6060", "[::ffff:127.0.0.1%lo0]:6060"}},
			"bad_port":         {bad: []string{"127.0.0.1", "127.0.0.1:", "127.0.0.1:http", "127.0.0.1:-1", "127.0.0.1:65536", "127.0.0.1:+1", "127.0.0.1:1\n"}},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				if tt.bad != nil {
					for _, input := range tt.bad {
						actual, err := parseAddress(input)
						if _, ok := errors.AsType[*options.OptionsError](err); !ok || actual != "" {
							t.Fatalf("parseAddress(%q) = %q, %v; want empty result and OptionsError", input, actual, err)
						}
					}
					return
				}
				actual, err := parseAddress(tt.input)
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(tt.want, actual); diff != "" {
					t.Fatalf("validated address mismatch (-want +got):\n%s", diff)
				}
			})
		}
	})
}
