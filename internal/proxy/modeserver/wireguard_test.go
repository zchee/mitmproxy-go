// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
)

func TestWireGuardModeErrors(t *testing.T) {
	tests := map[string]struct {
		config string
		occupy bool
	}{
		"error: invalid configuration": {config: "{"},
		"error: UDP address in use":    {occupy: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			path := filepath.Join(t.TempDir(), "wireguard.conf")
			if tt.config != "" {
				if err := os.WriteFile(path, []byte(tt.config), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			address := "127.0.0.1:0"
			if tt.occupy {
				socket, err := net.ListenPacket("udp", address)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = socket.Close() })
				address = socket.LocalAddr().String()
			}
			instance := makeInstance(t, "wireguard:"+path+"@"+address, cfg)
			t.Cleanup(func() { _ = instance.Stop() })
			err := instance.Start(t.Context())
			if err == nil || instance.IsRunning() || len(instance.ListenAddrs()) != 0 || instance.LastError() == nil {
				t.Fatalf("failed startup state: %v", err)
			}
			if tt.occupy {
				if !isAddrInUse(err) {
					t.Fatalf("UDP bind error = %v", err)
				}
			} else if !strings.Contains(err.Error(), "Invalid configuration file") {
				t.Fatalf("config error = %v", err)
			}
		})
	}
}

func TestWireGuardModeLifecycle(t *testing.T) {
	tests := map[string]struct {
		host     string
		canceled bool
	}{
		"IPv4 start stop restart": {host: "127.0.0.1"},
		"IPv6 start stop restart": {host: "::1"},
		"error: canceled startup": {host: "127.0.0.1", canceled: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			path := filepath.Join(t.TempDir(), "wireguard.conf")
			mode, err := modespec.Parse("wireguard:" + path + "@" + net.JoinHostPort(tt.host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			instance, err := New(mode, cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = instance.Stop() })
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.canceled {
				cancel()
			}
			err = instance.Start(ctx)
			if tt.canceled {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("Start = %v", err)
				}
				if instance.IsRunning() || len(instance.ListenAddrs()) != 0 {
					t.Fatal("canceled mode published a listener")
				}
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("canceled startup created config: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !instance.IsRunning() || len(instance.ListenAddrs()) != 1 || instance.ListenAddrs()[0].Port == 0 {
				t.Fatal("WireGuard listener not published")
			}
			config, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			original := sha256.Sum256(config)
			if err := instance.Start(ctx); err != nil {
				t.Fatal(err)
			}
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
			if instance.IsRunning() || len(instance.ListenAddrs()) != 0 {
				t.Fatal("stopped source remains published")
			}
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
			if err := instance.Start(ctx); err != nil {
				t.Fatal(err)
			}
			config, err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(config) != original {
				t.Fatal("restart replaced operator keys")
			}
		})
	}
}
