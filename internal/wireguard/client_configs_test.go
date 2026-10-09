// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"errors"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

// TestClientConfigs certifies the new rendering API; TestClientConfig separately
// preserves the legacy bytes against the pinned upstream configuration text.
func TestClientConfigs(t *testing.T) {
	legacy, err := LoadConfig("../../testdata/wg-test-client/test.conf")
	if err != nil {
		t.Fatal(err)
	}
	const second = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	firstText, err := legacy.ClientConfig("127.0.0.1", 51820)
	if err != nil {
		t.Fatal(err)
	}
	secondText := strings.Replace(firstText, legacy.ClientKey, second, 1)
	secondText = strings.Replace(secondText, "Address = 10.0.0.1/32", "Address = 10.0.0.2/32", 1)
	tests := map[string]struct {
		configuration Config
		want          []string
		wantError     error
	}{
		"success: legacy single peer": {configuration: legacy, want: []string{firstText}},
		"success: ordered peers": {
			configuration: Config{ServerKey: legacy.ServerKey, ClientKeys: []string{legacy.ClientKey, second}},
			want:          []string{firstText, secondText},
		},
		"error: invalid server": {configuration: Config{ClientKey: legacy.ClientKey}, wantError: errInvalidKey},
		"error: empty peers":    {configuration: Config{ServerKey: legacy.ServerKey, ClientKeys: []string{}}, wantError: ErrEmptyClientKeys},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := test.configuration.ClientConfigs("127.0.0.1", 51820)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("render error = %v, want %v", err, test.wantError)
			}
			if err != nil {
				return
			}
			if diff := gocmp.Diff(test.want, got); diff != "" {
				t.Errorf("client configurations (-want +got):\n%s", diff)
			}
			first, err := test.configuration.ClientConfig("127.0.0.1", 51820)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.want[0], first); diff != "" {
				t.Errorf("first configuration (-want +got):\n%s", diff)
			}
		})
	}
}
