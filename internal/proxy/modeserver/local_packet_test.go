// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/internal/local"
	"github.com/zchee/mitmproxy-go/options"
)

func TestMain(m *testing.M) {
	if os.Getenv("LOCAL_PACKET_PEER_RUNTIME") == "1" {
		os.Exit(runLocalPacketPeer(os.Args[1]))
	}
	os.Exit(m.Run())
}

// This process speaks the native Unix-datagram protocol to the landed Linux
// redirector. It is an IPC fixture, not an eBPF interception implementation.
func runLocalPacketPeer(dir string) int {
	peer, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: filepath.Join(dir, "redirector"), Net: "unixgram"})
	if err != nil {
		return 1
	}
	defer func() { _ = peer.Close() }()
	packet, err := os.ReadFile(os.Getenv("LOCAL_PACKET_INPUT"))
	if err != nil {
		return 1
	}
	if err := os.WriteFile(os.Getenv("LOCAL_PACKET_RUNTIME_DIR"), []byte(dir), 0o600); err != nil && os.Getenv("LOCAL_PACKET_RUNTIME_DIR") != "" {
		return 1
	}
	driver, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: filepath.Join(dir, "inject"), Net: "unixgram"})
	if err != nil {
		return 1
	}
	defer func() { _ = driver.Close() }()
	ready := make(chan *net.UnixAddr, 1)
	var workers sync.WaitGroup
	defer workers.Wait()
	workers.Go(func() {
		selectClient := <-ready
		data := make([]byte, 131072)
		for {
			n, _, err := driver.ReadFromUnix(data)
			if err != nil {
				return
			}
			if _, err := peer.WriteToUnix(data[:n], selectClient); err != nil {
				return
			}
		}
	})
	defer func() {
		_ = driver.Close()
		select {
		case ready <- nil:
		default:
		}
	}()
	if _, err := fmt.Fprintln(os.Stdout, filepath.Join(dir, "redirector")); err != nil {
		return 1
	}
	buf := make([]byte, 131072)
	for {
		n, client, err := peer.ReadFromUnix(buf)
		if err != nil {
			return 1
		}
		if n == 0 {
			return 0
		}
		var message local.FromProxy
		if err := proto.Unmarshal(buf[:n], &message); err != nil {
			return 1
		}
		if conf := message.GetInterceptConf(); conf != nil && len(conf.Actions) != 0 {
			select {
			case ready <- client:
			default:
			}
			if len(packet) != 0 {
				if _, err := peer.WriteToUnix(packet, client); err != nil {
					return 1
				}
			}
		}
		if reply := message.GetPacket(); reply != nil {
			receiver, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: os.Getenv("LOCAL_PACKET_OUTPUT"), Net: "unixgram"})
			if err != nil {
				return 1
			}
			_, err = receiver.Write(reply.Data)
			_ = receiver.Close()
			if err != nil {
				return 1
			}
		}
	}
}

func TestLocalLinuxPacketIPCTCPOrigin(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}
	tests := map[string]struct{ network, host, source string }{
		"IPv4 TCP native packet driver": {"tcp4", "127.0.0.1", "10.0.0.1:4242"},
		"IPv6 TCP native packet driver": {"tcp6", "::1", "[fd00::1]:4242"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			input := filepath.Join(root, "input")
			if err := os.WriteFile(input, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			output := "@local-tcp-" + strconv.Itoa(os.Getpid()) + "-" + filepath.Base(root)
			replies, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: output, Net: "unixgram"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = replies.Close() })
			if err := replies.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			runtimeFile := filepath.Join(root, "runtime")
			t.Setenv("LOCAL_PACKET_INPUT", input)
			t.Setenv("LOCAL_PACKET_OUTPUT", output)
			t.Setenv("LOCAL_PACKET_RUNTIME_DIR", runtimeFile)
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			starter := filepath.Join(root, "starter")
			if err := os.WriteFile(starter, []byte("#!/bin/sh\nexport LOCAL_PACKET_PEER_RUNTIME=1\nexec "+strconv.Quote(binary)+" \"$1\"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "sudo"), []byte("#!/bin/sh\nif [ \"$1\" = echo ]; then exit 0; fi\nshift\nshift\nexec \"$@\"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
			redirector := local.NewLinuxRedirector(root, starter)
			t.Cleanup(func() { _ = redirector.Close() })
			cfg, m, _ := fixture(t)
			if err := m.Options.Add(t.Context(), "connection_strategy", options.TypeStr, "lazy", "When to establish origin connections."); err != nil {
				t.Fatal(err)
			}
			if err := m.Addons.Add(t.Context(), nextlayer.New(m.Options)); err != nil {
				t.Fatal(err)
			}
			instance := localIPCMode(t, cfg, redirector, "local")
			t.Cleanup(func() { _ = instance.Stop() })
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			runtimeDir, err := os.ReadFile(runtimeFile)
			if err != nil {
				t.Fatal(err)
			}
			sender, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: filepath.Join(string(runtimeDir), "inject"), Net: "unixgram"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sender.Close() })
			device := tuntest.NewChannelTUN()
			ctx, cancel := context.WithCancel(t.Context())
			var workers sync.WaitGroup
			t.Cleanup(func() { cancel(); _ = replies.Close(); _ = sender.Close(); workers.Wait() })
			workers.Go(func() {
				for {
					select {
					case data := <-device.Outbound:
						wire, err := proto.Marshal(&local.PacketWithMeta{Data: data, TunnelInfo: &local.TunnelInfo{Pid: new(uint32(42)), ProcessName: new("curl")}})
						if err != nil {
							t.Error(err)
							return
						}
						if _, err := sender.Write(wire); err != nil {
							if ctx.Err() == nil {
								t.Error(err)
							}
							return
						}
					case <-ctx.Done():
						return
					}
				}
			})
			workers.Go(func() {
				buf := make([]byte, 65535)
				for {
					n, _, err := replies.ReadFromUnix(buf)
					if err != nil {
						if ctx.Err() == nil {
							t.Error(err)
						}
						return
					}
					data := append([]byte(nil), buf[:n]...)
					select {
					case device.Inbound <- data:
					case <-ctx.Done():
						return
					}
				}
			})
			origin, err := net.Listen(tt.network, net.JoinHostPort(tt.host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = origin.Close() })
			if err := origin.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			peer := tunTCPPeer(t, instance, device, netip.MustParseAddrPort(tt.source), origin.Addr().(*net.TCPAddr).AddrPort())
			if _, err := io.WriteString(peer, "native-packet-tcp"); err != nil {
				t.Fatal(err)
			}
			conn, err := origin.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, len("native-packet-tcp"))
			if _, err := io.ReadFull(conn, data); err != nil || string(data) != "native-packet-tcp" {
				t.Fatalf("originTCP=%q,%v", data, err)
			}
			if _, err := conn.Write(data); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(peer, data); err != nil || string(data) != "native-packet-tcp" {
				t.Fatalf("nativeTCP=%q,%v", data, err)
			}
			// Join the packet driver before testing cancels the process context;
			// otherwise the daemon socket can disappear while its sender is live.
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
			cancel()
			_ = replies.Close()
			_ = sender.Close()
			workers.Wait()
			if err := redirector.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLocalLinuxPacketIPCOrigin(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}
	tests := map[string]struct{ network, host, source string }{
		"IPv4 native datagram to UDP origin": {"udp4", "127.0.0.1", "10.0.0.1:4242"},
		"IPv6 native datagram to UDP origin": {"udp6", "::1", "[fd00::1]:4242"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			origin, err := net.ListenPacket(tt.network, net.JoinHostPort(tt.host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = origin.Close() }()
			if err := origin.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			packet := tunUDPTestPacket(netip.MustParseAddrPort(tt.source), origin.LocalAddr().(*net.UDPAddr).AddrPort(), []byte("packet-ipc"))
			wire, err := proto.Marshal(&local.PacketWithMeta{Data: packet, TunnelInfo: &local.TunnelInfo{Pid: new(uint32(42)), ProcessName: new("curl")}})
			if err != nil {
				t.Fatal(err)
			}
			input := filepath.Join(root, "input")
			output := "@local-packet-" + strconv.Itoa(os.Getpid()) + "-" + filepath.Base(root)
			replies, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: output, Net: "unixgram"})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = replies.Close() }()
			if err := replies.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(input, wire, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("LOCAL_PACKET_INPUT", input)
			t.Setenv("LOCAL_PACKET_OUTPUT", output)
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			starter := filepath.Join(root, "starter")
			if err := os.WriteFile(starter, []byte("#!/bin/sh\nexport LOCAL_PACKET_PEER_RUNTIME=1\nexec "+strconv.Quote(binary)+" \"$1\"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "sudo"), []byte("#!/bin/sh\nif [ \"$1\" = echo ]; then exit 0; fi\nshift\nshift\nexec \"$@\"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
			redirector := local.NewLinuxRedirector(root, starter)
			t.Cleanup(func() { _ = redirector.Close() })
			cfg, m, hooks := fixture(t)
			if err := m.Options.Add(t.Context(), "connection_strategy", options.TypeStr, "lazy", "When to establish origin connections."); err != nil {
				t.Fatal(err)
			}
			if err := m.Addons.Add(t.Context(), nextlayer.New(m.Options)); err != nil {
				t.Fatal(err)
			}
			instance := localIPCMode(t, cfg, redirector, "local")
			t.Cleanup(func() { _ = instance.Stop() })
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			n, client, err := origin.ReadFrom(buf)
			if err != nil || string(buf[:n]) != "packet-ipc" {
				t.Fatalf("origin request = %q, %v", buf[:n], err)
			}
			if _, err := origin.WriteTo(buf[:n], client); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 65535)
			n, _, err = replies.ReadFromUnix(reply)
			if err != nil {
				t.Fatal(err)
			}
			var payload []byte
			if tt.network == "udp4" {
				payload = header.IPv4(reply[:n]).Payload()
			} else {
				payload = header.IPv6(reply[:n]).Payload()
			}
			if got := string(header.UDP(payload).Payload()); got != "packet-ipc" {
				t.Fatalf("native IPC reply payload = %q", got)
			}
			if mode := await(t, hooks.connected); mode != "local" {
				t.Fatalf("hook mode = %q", mode)
			}
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
