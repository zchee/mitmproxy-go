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

// TestWireGuardClientConfigurationPrinting is a regression for the missing
// startup output; the rendered legacy text remains byte-identical to upstream.
func TestWireGuardClientConfigurationPrinting(t *testing.T) {
	tests := map[string]struct{ host string }{
		"success: legacy configuration after readiness": {host: "127.0.0.1"},
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
			want, err := configuration.ClientConfig(test.host, uint16(address.Port))
			if err != nil {
				t.Fatal(err)
			}
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			logs := output.String()
			printed := strings.Index(logs, `"msg":`+string(encoded))
			ready := strings.Index(logs, "WireGuard server listening at")
			if ready < 0 || printed < ready || printed < 0 {
				t.Fatal("startup did not print the unchanged client configuration after readiness")
			}
		})
	}
}
