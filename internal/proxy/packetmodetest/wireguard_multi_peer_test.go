// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build packetmodes

package packetmodetest

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	wgnetstack "golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/zchee/mitmproxy-go/internal/wireguard"
)

// testWireGuardMultiplePeers extends the DumpMaster acceptance with the pinned
// first client and a userspace second client, using distinct keys and source IPs.
// Both must receive their own HELLO/HELLO WORLD! replies through the real addons.
func testWireGuardMultiplePeers(t *testing.T, binary, client, root string) {
	t.Helper()
	legacy, err := wireguard.LoadConfig(filepath.Join(root, "testdata/wg-test-client/test.conf"))
	if err != nil {
		t.Fatal(err)
	}
	const secondKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	configuration := wireguard.Config{ServerKey: legacy.ServerKey, ClientKeys: []string{legacy.ClientKey, secondKey}}
	data, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "wireguard.conf")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	p := startProcess(t, binary, []string{"-test.run", "^TestWireGuardExecutable$", "-test.v"}, []string{
		"PACKET_WIREGUARD_CHILD=1", "PACKET_WIREGUARD_MULTI=1", "PACKET_WIREGUARD_CONFIG=" + path,
	}, "wireguard-multi-proxy.log")
	port := p.ready(t, `WireGuard server listening at 127\.0\.0\.1:([0-9]+)\.`)
	network := secondWireGuardClient(t, legacy.ServerKey, secondKey, "127.0.0.1:"+port)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	type verdict struct {
		pinned bool
		output []byte
		err    error
	}
	results := make(chan verdict, 2)
	go func() {
		command := exec.CommandContext(ctx, client, port)
		output, err := command.CombinedOutput()
		results <- verdict{pinned: true, output: output, err: err}
	}()
	go func() { results <- verdict{err: secondWireGuardReplies(ctx, network)} }()
	for range 2 {
		select {
		case result := <-results:
			if result.pinned {
				if err := os.WriteFile(logPath(t, "wireguard-multi-pinned-client.log"), result.output, 0o644); err != nil {
					t.Fatal(err)
				}
				if result.err != nil {
					t.Fatalf("pinned client in multi-peer exchange: %v\n%s", result.err, result.output)
				}
				for _, marker := range []string{"It's the UDP reply we were looking for.", "It's a TCP ACK with the data we were looking for.", "All set!"} {
					if !strings.Contains(string(result.output), marker) {
						t.Fatalf("pinned client lacks verdict %q", marker)
					}
				}
			} else if result.err != nil {
				t.Fatalf("second encrypted peer: %v", result.err)
			}
		case <-ctx.Done():
			t.Fatal("concurrent WireGuard clients did not finish within their exchange budget")
		}
	}
	p.stop(t)
}

func secondWireGuardClient(t *testing.T, serverText, clientText, endpoint string) *wgnetstack.Net {
	t.Helper()
	serverBytes, err := base64.StdEncoding.DecodeString(serverText)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdh.X25519().NewPrivateKey(serverBytes)
	if err != nil {
		t.Fatal(err)
	}
	clientBytes, err := base64.StdEncoding.DecodeString(clientText)
	if err != nil {
		t.Fatal(err)
	}
	var private device.NoisePrivateKey
	if err := private.FromHex(hex.EncodeToString(clientBytes)); err != nil {
		t.Fatal(err)
	}
	tunnel, network, err := wgnetstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	engine := device.NewDevice(tunnel, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(engine.Close)
	configuration := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\n", hex.EncodeToString(private[:]), hex.EncodeToString(serverKey.PublicKey().Bytes()), endpoint)
	if err := engine.IpcSet(configuration); err != nil {
		t.Fatal(err)
	}
	if err := engine.Up(); err != nil {
		t.Fatal(err)
	}
	return network
}

func secondWireGuardReplies(ctx context.Context, network *wgnetstack.Net) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("client exchange requires a deadline")
	}
	udp, err := network.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.0.0.42:31337"))
	if err != nil {
		return err
	}
	defer func() { _ = udp.Close() }()
	if err := udp.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := udp.Write([]byte("hello")); err != nil {
		return err
	}
	buffer := make([]byte, 64)
	n, err := udp.Read(buffer)
	if err != nil {
		return err
	}
	if string(buffer[:n]) != "HELLO" {
		return fmt.Errorf("UDP reply = %q, want HELLO", buffer[:n])
	}
	tcp, err := network.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.0.0.42:80"))
	if err != nil {
		return err
	}
	defer func() { _ = tcp.Close() }()
	if err := tcp.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := io.WriteString(tcp, "hello world!"); err != nil {
		return err
	}
	if _, err := io.ReadFull(tcp, buffer[:len("HELLO WORLD!")]); err != nil {
		return err
	}
	if string(buffer[:len("HELLO WORLD!")]) != "HELLO WORLD!" {
		return fmt.Errorf("TCP reply = %q, want HELLO WORLD!", buffer[:len("HELLO WORLD!")])
	}
	return nil
}
