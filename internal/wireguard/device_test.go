// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// TestDeviceEncryptedRoundTrip mirrors wireguard-go's device/device_test.go
// TestTwoDevicePing with real UDP sockets, including close ownership and restart.
func TestDeviceEncryptedRoundTrip(t *testing.T) {
	tests := map[string]struct{ restart bool }{
		"success: encrypted packets": {},
		"success: restart bindings":  {restart: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			var engines [2]*device.Device
			defer func() {
				for _, engine := range engines {
					if engine != nil {
						engine.Close()
						engine.Close()
						select {
						case <-engine.Wait():
						default:
							t.Error("Close returned before device completion")
						}
					}
				}
			}()
			var keys [2]*ecdh.PrivateKey
			var tunnels [2]*tuntest.ChannelTUN
			var endpoints [2]string
			addresses := [2]netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}
			for i := range keys {
				key, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				keys[i] = key
			}
			for i := range engines {
				tunnels[i] = tuntest.NewChannelTUN()
				engines[i] = newDevice(tunnels[i].TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
				configuration := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=%s/32\n",
					hex.EncodeToString(keys[i].Bytes()), hex.EncodeToString(keys[i^1].PublicKey().Bytes()), addresses[i^1])
				if err := engines[i].IpcSet(configuration); err != nil {
					t.Fatalf("configure device: %v", err)
				}
				if test.restart {
					if err := engines[i].Up(); err != nil {
						t.Fatalf("bring up device before restart: %v", err)
					}
					if err := engines[i].Down(); err != nil {
						t.Fatalf("bring down device: %v", err)
					}
				}
				if err := engines[i].Up(); err != nil {
					t.Fatalf("bring up device: %v", err)
				}
				configuration, err := engines[i].IpcGet()
				if err != nil {
					t.Fatalf("read listener port: %v", err)
				}
				for line := range strings.SplitSeq(configuration, "\n") {
					if port, ok := strings.CutPrefix(line, "listen_port="); ok {
						endpoints[i] = "127.0.0.1:" + port
					}
				}
				if endpoints[i] == "" || endpoints[i] == "127.0.0.1:0" {
					t.Fatal("device did not bind an ephemeral UDP port")
				}
			}
			for i, engine := range engines {
				configuration := fmt.Sprintf("public_key=%s\nendpoint=%s\n", hex.EncodeToString(keys[i^1].PublicKey().Bytes()), endpoints[i^1])
				if err := engine.IpcSet(configuration); err != nil {
					t.Fatalf("configure peer endpoint: %v", err)
				}
			}
			for i := range engines {
				packet := tuntest.Ping(addresses[i^1], addresses[i])
				select {
				case tunnels[i].Outbound <- packet:
				case <-ctx.Done():
					deviceTestTimeout(t, ctx)
				}
				select {
				case received := <-tunnels[i^1].Inbound:
					if diff := gocmp.Diff(packet, received); diff != "" {
						t.Fatalf("decrypted packet (-want +got):\n%s", diff)
					}
				case <-ctx.Done():
					deviceTestTimeout(t, ctx)
				}
			}
		})
	}
}

func deviceTestTimeout(t *testing.T, ctx context.Context) {
	t.Helper()
	var stack bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&stack, 2); err != nil {
		t.Fatalf("packet wait: %v; goroutine dump: %v", ctx.Err(), err)
	}
	t.Fatalf("packet wait: %v\n%s", ctx.Err(), stack.Bytes())
}
