// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"bytes"
	json "encoding/json/v2"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/wireguard"
)

// TestWireGuardClientConfigurationPrinting preserves existing single-peer output.
// The ordered-peer row is a regression for startup rejecting the multi-key form.
func TestWireGuardClientConfigurationPrinting(t *testing.T) {
	tests := map[string]struct {
		host  string
		multi bool
	}{
		"success: legacy configuration after readiness": {host: "127.0.0.1"},
		"success: ordered peer configurations":          {host: "127.0.0.1", multi: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			var output bytes.Buffer
			cfg.Logger = slog.New(slog.NewJSONHandler(&output, nil))
			data, err := os.ReadFile("../../../testdata/wg-test-client/test.conf")
			if err != nil {
				t.Fatal(err)
			}
			if test.multi {
				var legacy wireguard.Config
				if err := json.Unmarshal(data, &legacy); err != nil {
					t.Fatal(err)
				}
				data, err = json.Marshal(wireguard.Config{ServerKey: legacy.ServerKey, ClientKeys: []string{legacy.ClientKey, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}})
				if err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(t.TempDir(), "wireguard.conf")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			instance := makeInstance(t, "wireguard:"+path+"@"+test.host+":0", cfg)
			t.Cleanup(func() { _ = instance.Stop() })
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			address := instance.ListenAddrs()[0]
			configuration, err := wireguard.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			want, err := configuration.ClientConfigs(test.host, uint16(address.Port))
			if err != nil {
				t.Fatal(err)
			}
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
			logs := output.String()
			previous := strings.Index(logs, "WireGuard server listening at")
			if previous < 0 {
				t.Fatal("startup did not publish listener readiness")
			}
			for _, text := range want {
				encoded, err := json.Marshal(text)
				if err != nil {
					t.Fatal(err)
				}
				printed := strings.Index(logs, `"msg":`+string(encoded))
				if printed <= previous {
					t.Fatal("startup did not print ordered client configurations after readiness")
				}
				previous = printed
			}
		})
	}
}
