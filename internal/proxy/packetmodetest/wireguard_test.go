// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build packetmodes

package packetmodetest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/tools/cmdline"
	"github.com/zchee/mitmproxy-go/internal/tools/dump"
)

type uppercaseAddon struct {
	tcp *connection.Address
	udp *connection.Address
}

// Name distinguishes this fixture addon from the production default set.
func (*uppercaseAddon) Name() string { return "packet-uppercase" }

// TCPStart directs the fixture's fixed destination to a real loopback origin.
func (a *uppercaseAddon) TCPStart(_ context.Context, f *flow.TCPFlow) error {
	f.ServerConn.Address = a.tcp
	return nil
}

// UDPStart directs the fixture's fixed destination to a real loopback origin.
func (a *uppercaseAddon) UDPStart(_ context.Context, f *flow.UDPFlow) error {
	f.ServerConn.Address = a.udp
	return nil
}

// TCPMessage uppercases client bytes through the production message hook.
func (*uppercaseAddon) TCPMessage(_ context.Context, f *flow.TCPFlow) error {
	message := f.Messages[len(f.Messages)-1]
	if message.FromClient {
		message.Content = bytes.ToUpper(message.Content)
	}
	return nil
}

// UDPMessage uppercases client datagrams through the production message hook.
func (*uppercaseAddon) UDPMessage(_ context.Context, f *flow.UDPFlow) error {
	message := f.Messages[len(f.Messages)-1]
	if message.FromClient {
		message.Content = bytes.ToUpper(message.Content)
	}
	return nil
}

// TestWireGuardExecutable drives the pinned client through the stock DumpMaster,
// proxyserver, Handler and flow hooks. Only addon loading differs from the CLI:
// script addon loading (-s) is not ported; the row substitutes Manager.Add.
func TestWireGuardExecutable(t *testing.T) {
	if os.Getenv("PACKET_WIREGUARD_CHILD") == "1" {
		runWireGuardDump(t)
		return
	}
	tests := map[string]struct {
		fixture string
		multi   bool
	}{
		"success: upstream encrypted TCP and UDP replies": {fixture: "test.conf"},
		"success: concurrent encrypted peers":             {fixture: "test.conf", multi: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			clientName := map[string]string{
				"linux/amd64": "linux-x86_64", "darwin/arm64": "macos-aarch64",
				"darwin/amd64": "macos-x86_64", "windows/amd64": "windows-x86_64.exe",
			}[runtime.GOOS+"/"+runtime.GOARCH]
			if clientName == "" {
				t.Fatalf("required WireGuard fixture unavailable for %s/%s", runtime.GOOS, runtime.GOARCH)
			}
			root := sourceRoot(t)
			client := filepath.Join(root, "testdata/wg-test-client", clientName)
			if info, err := os.Stat(client); err != nil || info.Size() == 0 {
				t.Fatalf("missing required WireGuard executable %s: %v", client, err)
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			if tt.multi {
				testWireGuardMultiplePeers(t, binary, client, root)
				return
			}
			p := startProcess(t, binary, []string{"-test.run", "^TestWireGuardExecutable$", "-test.v"}, []string{
				"PACKET_WIREGUARD_CHILD=1", "PACKET_WIREGUARD_CONFIG=" + filepath.Join(root, "testdata/wg-test-client", tt.fixture),
			}, "wireguard-proxy.log")
			port := p.ready(t, `WireGuard server listening at 127\.0\.0\.1:([0-9]+)\.`)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, client, port)
			output, err := command.CombinedOutput()
			if writeErr := os.WriteFile(logPath(t, "wireguard-client.log"), output, 0o644); writeErr != nil {
				t.Fatal(writeErr)
			}
			if err != nil {
				t.Fatalf("upstream WireGuard client: %v\n%s", err, output)
			}
			for _, marker := range []string{"It's the UDP reply we were looking for.", "It's a TCP ACK with the data we were looking for.", "All set!"} {
				if !strings.Contains(string(output), marker) {
					t.Fatalf("missing required fixture verdict %q\n%s", marker, output)
				}
			}
			p.stop(t)
		})
	}
}

func runWireGuardDump(t *testing.T) {
	t.Helper()
	ctx, cancel := signal.NotifyContext(t.Context(), os.Interrupt)
	defer cancel()
	tcpOrigin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcpOrigin.Close() }()
	udpOrigin, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udpOrigin.Close() }()
	// The pinned client targets 10.0.0.42:80 and :31337. Retarget through
	// addon hooks, not a replacement peer or a bypass of the Handler.
	tcpHost, tcpPort := address(t, tcpOrigin.Addr().String())
	udpHost, udpPort := address(t, udpOrigin.LocalAddr().String())
	peerCount := 1
	if os.Getenv("PACKET_WIREGUARD_MULTI") == "1" {
		peerCount = 2
	}
	originErrors := make(chan error, 2*peerCount)
	go func() {
		for range peerCount {
			peer, err := tcpOrigin.Accept()
			if err != nil {
				originErrors <- err
				return
			}
			_ = peer.SetDeadline(time.Now().Add(30 * time.Second))
			content := make([]byte, len("HELLO WORLD!"))
			_, err = io.ReadFull(peer, content)
			if err == nil && string(content) != "HELLO WORLD!" {
				err = errors.New("TCP addon did not uppercase the client message")
			}
			if err == nil {
				_, err = peer.Write(content)
			}
			_ = peer.Close()
			originErrors <- err
		}
	}()
	go func() {
		_ = udpOrigin.SetDeadline(time.Now().Add(30 * time.Second))
		content := make([]byte, 65535)
		for range peerCount {
			n, peer, err := udpOrigin.ReadFrom(content)
			if err == nil && string(content[:n]) != "HELLO" {
				err = errors.New("UDP addon did not uppercase the client datagram")
			}
			if err == nil {
				_, err = udpOrigin.WriteTo(content[:n], peer)
			}
			originErrors <- err
		}
	}()
	m, err := dump.New(ctx, dump.Config{Stdout: os.Stdout, Stderr: os.Stderr, WithTermlog: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close(context.WithoutCancel(ctx)) }()
	cmd := cmdline.New(m.Options, "packet acceptance")
	if err := cmd.ParseFlags([]string{"--mode", "wireguard:" + os.Getenv("PACKET_WIREGUARD_CONFIG") + "@127.0.0.1:0", "--set", "confdir=" + privateDirectory(t), "--set", "connection_strategy=lazy", "--set", "tcp_hosts=.*"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdline.Apply(ctx, cmd, m.Options, m.Do); err != nil {
		t.Fatal(err)
	}
	if err := m.Addons.Add(ctx, &uppercaseAddon{tcp: &connection.Address{Host: tcpHost, Port: tcpPort}, udp: &connection.Address{Host: udpHost, Port: udpPort}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for range 2 * peerCount {
		select {
		case err := <-originErrors:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("WireGuard origin completion hang detector")
		}
	}
}
