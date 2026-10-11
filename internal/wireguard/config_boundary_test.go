// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/internal/netstack"
)

// TestConfigPeerCountBoundary certifies the configured-peer policy boundary.
// The parent accepts 256 peers and crosses into the next /24, not an invalid IP.
// Programmatic Config avoids changing the independent 4096-byte file limit.
func TestConfigPeerCountBoundary(t *testing.T) {
	tests := map[string]struct {
		count     int
		wantError string
	}{
		"success: one peer":                   {count: 1},
		"success: last address in the subnet": {count: 255},
		"error: too many peers":               {count: 256, wantError: "client_keys must contain at most 255 peers"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			configuration := peerBoundaryConfig(test.count)
			keys, peerErr := configuration.PeerKeys()
			first, firstErr := configuration.ClientConfig("localhost", 51820)
			configs, configsErr := configuration.ClientConfigs("localhost", 51820)
			for _, err := range []error{peerErr, firstErr, configsErr} {
				if test.wantError != "" {
					if err == nil || err.Error() != test.wantError {
						t.Fatalf("peer boundary error = %v, want %q", err, test.wantError)
					}
					for _, key := range configuration.ClientKeys {
						if strings.Contains(err.Error(), key) {
							t.Fatal("peer boundary error exposed private material")
						}
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if test.wantError != "" {
				if keys != nil || configs != nil || first != "" {
					t.Fatal("rejected peer list returned partial keys or configurations")
				}
				return
			}
			if diff := gocmp.Diff(configuration.ClientKeys, keys); diff != "" {
				t.Errorf("ordered peers (-want +got):\n%s", diff)
			}
			if len(configs) != test.count || first != configs[0] {
				t.Fatal("rendering changed the peer count or first configuration")
			}
			addresses := make(map[netip.Prefix]struct{}, test.count)
			for i, config := range configs {
				found := false
				for line := range strings.SplitSeq(config, "\n") {
					if text, ok := strings.CutPrefix(line, "Address = "); ok {
						address, err := netip.ParsePrefix(text)
						want := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), 32)
						if err != nil || address != want {
							t.Fatalf("peer %d address = %v (%v), want %v", i, address, err, want)
						}
						addresses[address] = struct{}{}
						found = true
					}
				}
				if !found {
					t.Fatalf("peer %d has no printed address", i)
				}
			}
			if len(addresses) != test.count {
				t.Fatal("printed addresses are not distinct")
			}
		})
	}
}

func peerBoundaryConfig(count int) Config {
	configuration := Config{ServerKey: "EG47ZWjYjr+Y97TQ1A7sVl7Xn3mMWDnvjU/VxU769ls=", ClientKeys: make([]string, count)}
	for i := range count {
		var key [32]byte
		// Low scalar bits are clamped by X25519; vary bits above that range.
		binary.LittleEndian.PutUint32(key[:], uint32(i+1)<<3)
		configuration.ClientKeys[i] = base64.StdEncoding.EncodeToString(key[:])
	}
	return configuration
}

// TestPeerCountValidationOrder preserves form precedence and proves refusal
// before per-peer key validation and before the constructor's engine loop.
func TestPeerCountValidationOrder(t *testing.T) {
	tests := map[string]struct{ conflicting bool }{
		"error: excessive invalid list":      {},
		"error: conflicting forms still win": {conflicting: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
			configuration := peerBoundaryConfig(256)
			configuration.ClientKeys[0] = "invalid"
			want := "client_keys must contain at most 255 peers"
			if test.conflicting {
				configuration.ClientKey = "invalid"
				want = ErrConflictingClientKeys.Error()
			}
			keys, err := configuration.PeerKeys()
			if err == nil || err.Error() != want || keys != nil {
				t.Fatalf("validation order error = %v, want %q with no keys", err, want)
			}
			stack, err := netstack.New(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stack.Close() }()
			socket, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server, err := New(t.Context(), socket, configuration, stack, slog.New(slog.DiscardHandler))
			if server != nil {
				_ = server.Close()
				t.Fatal("excessive peer list started engines")
			}
			if err == nil || err.Error() != want {
				t.Fatalf("constructor error = %v, want %q", err, want)
			}
			if err := socket.SetReadDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("failed constructor retained socket: %v", err)
			}
		})
	}
}
