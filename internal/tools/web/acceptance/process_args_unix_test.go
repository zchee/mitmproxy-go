// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build (difftest || browser || webprivileged) && unix

package acceptance_test

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestMitmwebProcessArguments(t *testing.T) {
	tests := map[string]struct {
		tuple webInputTuple
		want  []string
	}{
		"owned fixed tuple": {
			tuple: webInputTuple{webPort: 12345, confdir: "/owned/conf"},
			want: []string{
				"--mode", "regular@127.0.0.1:18080", "--no-web-open-browser",
				"--web-host=127.0.0.1", "--web-port=12345", "--set", "confdir=/owned/conf",
				"--set", "web_password=" + webTestPassword,
			},
		},
		"fixture path remains one argument": {
			tuple: webInputTuple{webPort: 23456, confdir: "/owned/private conf", fixture: "/owned/captured flows.mitm"},
			want: []string{
				"--mode", "regular@127.0.0.1:18080", "--no-web-open-browser",
				"--web-host=127.0.0.1", "--web-port=23456", "--set", "confdir=/owned/private conf",
				"--set", "web_password=" + webTestPassword, "-r", "/owned/captured flows.mitm",
			},
		},
		"ephemeral web binding is explicit": {
			tuple: webInputTuple{webPort: 0, confdir: "/owned/ephemeral"},
			want: []string{
				"--mode", "regular@127.0.0.1:18080", "--no-web-open-browser",
				"--web-host=127.0.0.1", "--web-port=0", "--set", "confdir=/owned/ephemeral",
				"--set", "web_password=" + webTestPassword,
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, tt.tuple.goArgs()); diff != "" {
				t.Fatalf("Go executable arguments differ (-want +got):\n%s", diff)
			}
		})
	}
}
