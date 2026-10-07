// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestLoadConfig(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/wg-test-client/test.conf")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		data        []byte
		directory   bool
		generated   bool
		invalidKey  bool
		invalidFile bool
	}{
		"success: upstream fixture":         {data: fixture},
		"success: unknown fields":           {data: []byte(strings.TrimSuffix(strings.TrimSpace(string(fixture)), "}") + `,"extra":true}`)},
		"success: duplicate name last wins": {data: []byte(`{"server_key":"invalid",` + strings.TrimPrefix(strings.TrimSpace(string(fixture)), "{"))},
		"error: null server key":            {data: []byte(`{"server_key":null,"client_key":""}`), invalidFile: true},
		"error: nonstring server key":       {data: []byte(`{"server_key":42,"client_key":""}`), invalidFile: true},
		"success: generated and reused":     {generated: true},
		"error: directory":                  {directory: true, invalidFile: true},
		"error: truncated JSON":             {data: []byte(`{"server_key":`), invalidFile: true},
		"error: missing server key":         {data: []byte(`{"client_key":""}`), invalidFile: true},
		"error: missing client key":         {data: []byte(`{"server_key":""}`), invalidFile: true},
		"error: invalid server key":         {data: []byte(`{"server_key":"not-a-key","client_key":"qG8b7LI/s+ezngWpXqj5A7Nj988hbGL+eQ8ePki0iHk="}`), invalidKey: true},
		"error: invalid client key":         {data: []byte(`{"server_key":"EG47ZWjYjr+Y97TQ1A7sVl7Xn3mMWDnvjU/VxU769ls=","client_key":"not-a-key"}`), invalidKey: true},
		"error: oversized file":             {data: []byte(strings.Repeat(" ", maxConfigSize+1)), invalidFile: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nested", "wireguard.conf")
			if !test.generated {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if test.directory {
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(path, test.data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			configuration, err := LoadConfig(path)
			if test.invalidKey {
				// rs:mitmproxy-rs/src/util.rs:16-25 validates key text separately.
				if !errors.Is(err, errInvalidKey) || err.Error() != "Invalid key." {
					t.Fatalf("invalid key error = %v", err)
				}
				return
			}
			if test.invalidFile {
				// py:mitmproxy/proxy/mode_servers.py:364-369.
				if err == nil || !strings.HasPrefix(err.Error(), "Invalid configuration file ("+path+"): ") {
					t.Fatalf("invalid file error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			stored, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Config
			if err := json.Unmarshal(stored, &decoded, jsontext.AllowDuplicateNames(true)); err != nil {
				t.Fatal(err)
			}
			if !gocmp.Equal(configuration, decoded) {
				t.Error("stored keys differ from loaded keys")
			}
			reloaded, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			// py:test/mitmproxy/proxy/test_mode_servers.py:262-280.
			if !gocmp.Equal(configuration, reloaded) {
				t.Error("second start replaced the existing keys")
			}
			if !test.generated && !gocmp.Equal(test.data, stored) {
				t.Error("loading rewrote the existing configuration")
			}
			if test.generated {
				if configuration.ServerKey == configuration.ClientKey {
					t.Error("generated identical server and client keys")
				}
				for _, key := range []string{configuration.ServerKey, configuration.ClientKey} {
					if _, err := privateKey(key); err != nil {
						t.Fatalf("generated key is invalid: %v", err)
					}
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
					t.Errorf("private file permissions = %o, want 600", info.Mode().Perm())
				}
			}
		})
	}
}

func TestConfigConcurrentCreation(t *testing.T) {
	tests := map[string]struct{ count int }{
		"success: simultaneous first starts": {count: 8},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wireguard.conf")
			var group sync.WaitGroup
			configurations := make([]Config, test.count)
			failures := make([]error, test.count)
			for i := range test.count {
				group.Go(func() { configurations[i], failures[i] = LoadConfig(path) })
			}
			group.Wait()
			for i := range test.count {
				if failures[i] != nil {
					t.Errorf("reader %d: %v", i, failures[i])
				} else if !gocmp.Equal(configurations[0], configurations[i]) {
					t.Errorf("reader %d loaded different keys", i)
				}
			}
		})
	}
}

func TestClientConfig(t *testing.T) {
	configuration, err := LoadConfig("../../testdata/wg-test-client/test.conf")
	if err != nil {
		t.Fatal(err)
	}
	// Text from py:mitmproxy/proxy/mode_servers.py:393-414; public key from
	// rs:wireguard-test-client/src/main.rs:22-24, using the same fixture.
	const template = `[Interface]
PrivateKey = qG8b7LI/s+ezngWpXqj5A7Nj988hbGL+eQ8ePki0iHk=
Address = 10.0.0.1/32
DNS = 10.0.0.53

[Peer]
PublicKey = mitmV5Wo7pRJrHNAKhZEI0nzqqeO8u4fXG+zUbZEXA0=
AllowedIPs = 0.0.0.0/0
Endpoint = `
	tests := map[string]struct{ host, endpoint string }{
		"success: IPv4":                   {host: "127.0.0.1", endpoint: "127.0.0.1:51820"},
		"success: hostname":               {host: "example.test", endpoint: "example.test:51820"},
		"success: upstream IPv6 spelling": {host: "::1", endpoint: "::1:51820"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := configuration.ClientConfig(test.host, 51820)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(template+test.endpoint, got); diff != "" {
				t.Errorf("client configuration (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPrivateKey(t *testing.T) {
	tests := map[string]struct{ text string }{
		"error: empty":                     {},
		"error: malformed base64":          {text: strings.Repeat("!", 44)},
		"error: short decoded key":         {text: base64.StdEncoding.EncodeToString(make([]byte, 31))},
		"error: long decoded key":          {text: base64.StdEncoding.EncodeToString(make([]byte, 33))},
		"error: newline":                   {text: "EG47ZWjYjr+Y97TQ1A7sVl7Xn3mMWDnvjU/VxU769ls=\n"},
		"error: noncanonical padding bits": {text: "EG47ZWjYjr+Y97TQ1A7sVl7Xn3mMWDnvjU/VxU769lt="},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := privateKey(test.text); !errors.Is(err, errInvalidKey) {
				t.Fatalf("invalid key error = %v", err)
			}
		})
	}
}
