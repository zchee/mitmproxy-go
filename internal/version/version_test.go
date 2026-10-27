// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package version

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestVersion(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct {
			got  func() string
			want string
		}{
			"development_default": {
				got:  func() string { return Version },
				want: "0.1.0-dev",
			},
			"string_format": {
				got:  String,
				want: "mitmproxy-go 0.1.0-dev",
			},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				if diff := gocmp.Diff(tt.want, tt.got()); diff != "" {
					t.Errorf("version mismatch (-want +got):\n%s", diff)
				}
			})
		}
	})
}

func TestString(t *testing.T) {
	if got, want := String(), "mitmproxy-go 0.1.0-dev"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
