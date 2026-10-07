// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver_test

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
	"github.com/zchee/mitmproxy-go/internal/wireguard"
)

func modeWireGuardClient(t *testing.T, configurationPath, endpoint string, ipv6 bool) *modeClientNetwork {
	t.Helper()
	configuration, err := wireguard.LoadConfig(configurationPath)
	if err != nil {
		t.Fatal(err)
	}
	private, err := base64.StdEncoding.DecodeString(configuration.ClientKey)
	if err != nil {
		t.Fatal("invalid generated client key encoding")
	}
	serverPrivate, err := base64.StdEncoding.DecodeString(configuration.ServerKey)
	if err != nil {
		t.Fatal("invalid generated server key encoding")
	}
	serverKey, err := ecdh.X25519().NewPrivateKey(serverPrivate)
	if err != nil {
		t.Fatal("invalid generated server key")
	}
	address := netip.MustParseAddr("10.0.0.1")
	if ipv6 {
		address = netip.MustParseAddr("fd00::1")
	}
	tunnel, network, err := modeClientStack(t.Context(), address)
	if err != nil {
		t.Fatal(err)
	}
	engine := device.NewDevice(tunnel, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(engine.Close)
	settings := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n", hex.EncodeToString(private), hex.EncodeToString(serverKey.PublicKey().Bytes()), endpoint)
	if err := engine.IpcSet(settings); err != nil {
		t.Fatal("configure WireGuard test client failed")
	}
	if err := engine.Up(); err != nil {
		t.Fatal(err)
	}
	return network
}

func TestWireGuardModeEncryptedFlows(t *testing.T) {
	tests := map[string]struct{ protocol string }{
		"HTTP through transparent handler": {protocol: "http"},
		"TCP through raw handler":          {protocol: "tcp"},
		"UDP through packet handler":       {protocol: "udp"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var origin *proxytest.Origin
			switch tt.protocol {
			case "http":
				origin = proxytest.StartHTTPOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/wireguard" {
						t.Errorf("HTTP path = %q", r.URL.Path)
					}
					_, _ = io.WriteString(w, "wireguard-http")
				}))
			case "tcp":
				origin = proxytest.StartEchoOrigin(t)
			case "udp":
				origin = proxytest.StartUDPEchoOrigin(t)
			}
			p := proxytest.Start(t, proxytest.WithOptions(map[string]any{"mode": []string{"wireguard@127.0.0.1:0"}, "rawtcp": true}))
			network := modeWireGuardClient(t, filepath.Join(p.ConfDir, "wireguard.conf"), p.Addr, false)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			if tt.protocol == "udp" {
				destination := netip.MustParseAddrPort(origin.Addr)
				peer, err := network.DialUDPAddrPort(netip.AddrPort{}, destination)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = peer.Close() }()
				if err := peer.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err := peer.Write([]byte("wireguard-udp")); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 64)
				n, err := peer.Read(buf)
				if err != nil || string(buf[:n]) != "wireguard-udp" {
					var diagnostic []string
					if snapshotErr := p.Master.Do(t.Context(), func(context.Context) error {
						for _, call := range p.Recorder.Calls() {
							switch value := call.Arg.(type) {
							case *hookdata.NextLayer:
								diagnostic = append(diagnostic, fmt.Sprintf("%s: protocol=%s destination=%v selected=%v", call.Hook, value.Context.Client.TransportProtocol, value.Context.Server.Address, value.Layer))
							case *flow.UDPFlow:
								diagnostic = append(diagnostic, fmt.Sprintf("%s: destination=%v error=%v messages=%d", call.Hook, value.ServerConn.Address, value.Error, len(value.Messages)))
							}
						}
						return nil
					}); snapshotErr != nil {
						t.Fatal(snapshotErr)
					}
					t.Fatalf("UDP reply = %q, %v; hooks=%v; diagnostics=%v", buf[:n], err, p.Recorder.Hooks(), diagnostic)
				}
				return
			}
			peer, err := network.DialContext(ctx, "tcp", origin.Addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			if err := peer.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if tt.protocol == "http" {
				if _, err := io.WriteString(peer, "GET /wireguard HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(peer), nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != 200 || string(body) != "wireguard-http" {
					t.Fatalf("HTTP reply = %q, status=%d, %v", body, response.StatusCode, err)
				}
			} else {
				if _, err := io.WriteString(peer, "wireguard-tcp"); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, len("wireguard-tcp"))
				if _, err := io.ReadFull(peer, buf); err != nil || string(buf) != "wireguard-tcp" {
					t.Fatalf("TCP reply = %q, %v", buf, err)
				}
			}
		})
	}
}
