// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"encoding/base64"
	json "encoding/json/v2"
	"os"
	"path/filepath"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

// TestConfigPeerForms is a behavioural regression for the multi-key JSON form
// and its validation. The legacy row preserves the existing serialized bytes.
func TestConfigPeerForms(t *testing.T) {
	const serverKey = "EG47ZWjYjr+Y97TQ1A7sVl7Xn3mMWDnvjU/VxU769ls="
	const clientKey = "qG8b7LI/s+ezngWpXqj5A7Nj988hbGL+eQ8ePki0iHk="
	secondKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	aliasBytes := make([]byte, 32)
	aliasBytes[0] = 1 // X25519 ignores the low three bits of the private scalar.
	aliasKey := base64.StdEncoding.EncodeToString(aliasBytes)
	tests := map[string]struct {
		peerFields string
		wantJSON   string
		wantError  string
	}{
		"success: legacy bytes preserved": {
			peerFields: `"client_key":"` + clientKey + `"`,
			wantJSON:   `{"server_key":"` + serverKey + `","client_key":"` + clientKey + `"}`,
		},
		"success: ordered peers": {
			peerFields: `"client_keys":["` + clientKey + `","` + secondKey + `"]`,
			wantJSON:   `{"server_key":"` + serverKey + `","client_keys":["` + clientKey + `","` + secondKey + `"]}`,
		},
		"error: both forms": {
			peerFields: `"client_key":"` + clientKey + `","client_keys":["` + secondKey + `"]`,
			wantError:  "client_key and client_keys are mutually exclusive",
		},
		"error: null single form conflicts": {
			peerFields: `"client_key":null,"client_keys":["` + secondKey + `"]`,
			wantError:  "client_key and client_keys are mutually exclusive",
		},
		"error: null list conflicts": {
			peerFields: `"client_key":"` + clientKey + `","client_keys":null`,
			wantError:  "client_key and client_keys are mutually exclusive",
		},
		"error: empty list": {peerFields: `"client_keys":[]`, wantError: "client_keys must contain at least one peer"},
		"error: null list":  {peerFields: `"client_keys":null`, wantError: "client_keys must contain at least one peer"},
		"error: duplicate text": {
			peerFields: `"client_keys":["` + clientKey + `","` + clientKey + `"]`,
			wantError:  "client_keys contains duplicate peers",
		},
		"error: duplicate identity": {
			peerFields: `"client_keys":["` + secondKey + `","` + aliasKey + `"]`,
			wantError:  "client_keys contains duplicate peers",
		},
		"error: malformed peer": {peerFields: `"client_keys":["invalid"]`, wantError: "Invalid key."},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wireguard.conf")
			input := `{"server_key":"` + serverKey + `",` + test.peerFields + `}`
			if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}
			configuration, err := LoadConfig(path)
			if test.wantError != "" {
				if err == nil || err.Error() != test.wantError {
					t.Fatalf("configuration error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(configuration)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.wantJSON, string(encoded)); diff != "" {
				t.Errorf("configuration (-want +got):\n%s", diff)
			}
			stored, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(input, string(stored)); diff != "" {
				t.Errorf("loading changed configuration (-want +got):\n%s", diff)
			}
		})
	}
}
