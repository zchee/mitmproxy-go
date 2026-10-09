// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

// TestPeerKeys certifies the new API's ordering, ownership and named errors.
// The API is absent on the parent; that is absence evidence, not parent-red.
func TestPeerKeys(t *testing.T) {
	const first = "qG8b7LI/s+ezngWpXqj5A7Nj988hbGL+eQ8ePki0iHk="
	const second = "EG47ZWjYjr+Y97TQ1A7sVl7Xn3mMWDnvjU/VxU769ls="
	tests := map[string]struct {
		configuration Config
		want          []string
		wantError     error
	}{
		"success: legacy peer":    {configuration: Config{ClientKey: first}, want: []string{first}},
		"success: ordered peers":  {configuration: Config{ClientKeys: []string{first, second}}, want: []string{first, second}},
		"error: conflicting keys": {configuration: Config{ClientKey: first, ClientKeys: []string{second}}, wantError: ErrConflictingClientKeys},
		"error: empty peers":      {configuration: Config{ClientKeys: []string{}}, wantError: ErrEmptyClientKeys},
		"error: duplicate peers":  {configuration: Config{ClientKeys: []string{first, first}}, wantError: ErrDuplicateClientKeys},
		"error: missing peer":     {wantError: errInvalidKey},
		"error: malformed peer":   {configuration: Config{ClientKeys: []string{first, "invalid"}}, wantError: errInvalidKey},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := test.configuration.PeerKeys()
			if !errors.Is(err, test.wantError) {
				t.Fatalf("peer error = %v, want %v", err, test.wantError)
			}
			if err != nil {
				return
			}
			if diff := gocmp.Diff(test.want, got); diff != "" {
				t.Errorf("peers (-want +got):\n%s", diff)
			}
			got[0] = "changed"
			reloaded, err := test.configuration.PeerKeys()
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.want, reloaded); diff != "" {
				t.Errorf("caller mutated configuration (-want +got):\n%s", diff)
			}
		})
	}
}
