// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/options"
)

func TestTunModeAdmission(t *testing.T) {
	tests := map[string]struct {
		fallback int
	}{
		"tun":       {fallback: 8080},
		"tun:utun3": {fallback: -1},
	}
	for spec, tt := range tests {
		t.Run(spec, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			cfg.ListenPort = &tt.fallback
			mode, err := modespec.Parse(spec)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := New(mode, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if instance.IsRunning() || len(instance.ListenAddrs()) != 0 || instance.LastError() != nil {
				t.Fatal("validation opened a native interface")
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := instance.Start(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled start = %v", err)
			}
			if instance.IsRunning() || instance.LastError() == nil {
				t.Fatal("canceled source published running state")
			}
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTunModeLifecycle(t *testing.T) {
	tests := map[string]struct{ cancel bool }{
		"stop joins source":                {},
		"parent cancellation joins source": {cancel: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { goleak.VerifyNone(t) })
			cfg, _, _ := fixture(t)
			instance := makeInstance(t, "tun:utun3", cfg)
			var opens int
			var devices []*countedTunDevice
			instance.openTun = func(name string, _ *slog.Logger) (wgtun.Device, error) {
				if name != "utun3" {
					t.Fatalf("interface name = %q", name)
				}
				opens++
				dev := &countedTunDevice{Device: tuntest.NewChannelTUN().TUN()}
				devices = append(devices, dev)
				return dev, nil
			}
			t.Cleanup(func() { _ = instance.Stop() })
			for range 2 {
				ctx, cancel := context.WithCancel(t.Context())
				if err := instance.Start(ctx); err != nil {
					cancel()
					t.Fatal(err)
				}
				source := instance.state.Load().tun
				if !instance.IsRunning() || len(instance.ListenAddrs()) != 0 || source == nil {
					cancel()
					t.Fatal("no-port source running state")
				}
				if err := instance.Start(ctx); err != nil {
					cancel()
					t.Fatal(err)
				}
				if tt.cancel {
					cancel()
					select {
					case <-source.monitorDone:
					case <-time.After(30 * time.Second):
						t.Fatal("source cancellation hang detector")
					}
				} else {
					var workers sync.WaitGroup
					for range 3 {
						workers.Go(func() {
							if err := instance.Stop(); err != nil {
								t.Errorf("Stop = %v", err)
							}
						})
					}
					workers.Wait()
					cancel()
				}
				if instance.IsRunning() || len(instance.ListenAddrs()) != 0 || instance.LastError() != nil {
					t.Fatal("stopped native source state")
				}
				if err := instance.Stop(); err != nil {
					t.Fatal(err)
				}
			}
			if opens != 2 {
				t.Fatalf("native opens = %d, want 2", opens)
			}
			for _, dev := range devices {
				if calls := dev.closes.Load(); calls != 1 {
					t.Fatalf("device closes = %d, want 1", calls)
				}
			}
		})
	}
}

type countedTunDevice struct {
	wgtun.Device
	closes atomic.Int32
}

func (d *countedTunDevice) Close() error {
	d.closes.Add(1)
	return d.Device.Close()
}

func TestTunModeUDPOrigin(t *testing.T) {
	tests := map[string]struct{ network, host, source string }{
		"IPv4 native packet to origin": {"udp4", "127.0.0.1", "10.0.0.1:12345"},
		"IPv6 native packet to origin": {"udp6", "::1", "[fd00::1]:12345"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { goleak.VerifyNone(t) })
			cfg, m, hooks := fixture(t)
			if err := m.Options.Add(t.Context(), "connection_strategy", options.TypeStr, "lazy", "When to establish origin connections."); err != nil {
				t.Fatal(err)
			}
			if err := m.Addons.Add(t.Context(), nextlayer.New(m.Options)); err != nil {
				t.Fatal(err)
			}
			instance := makeInstance(t, "tun", cfg)
			channel := tuntest.NewChannelTUN()
			instance.openTun = func(_ string, _ *slog.Logger) (wgtun.Device, error) { return channel.TUN(), nil }
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = instance.Stop() })
			origin, err := net.ListenPacket(tt.network, net.JoinHostPort(tt.host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = origin.Close() }()
			if err := origin.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			destination := origin.LocalAddr().(*net.UDPAddr).AddrPort()
			packet := tunUDPTestPacket(netip.MustParseAddrPort(tt.source), destination, []byte("tun-request"))
			select {
			case channel.Outbound <- packet:
			case <-time.After(30 * time.Second):
				t.Fatal("packet admission hang detector")
			}
			buffer := make([]byte, 64)
			n, peer, err := origin.ReadFrom(buffer)
			if err != nil || string(buffer[:n]) != "tun-request" {
				t.Fatalf("origin request = %q, %v", buffer[:n], err)
			}
			if _, err := origin.WriteTo([]byte("tun-reply"), peer); err != nil {
				t.Fatal(err)
			}
			select {
			case reply, ok := <-channel.Inbound:
				if !ok {
					t.Fatal("packet device closed before response")
				}
				var payload []byte
				if destination.Addr().Is4() {
					payload = header.IPv4(reply).Payload()
				} else {
					payload = header.IPv6(reply).Payload()
				}
				if got := string(header.UDP(payload).Payload()); got != "tun-reply" {
					t.Fatalf("native reply = %q", got)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("native response hang detector")
			}
			if got := await(t, hooks.connected); got != "tun" {
				t.Fatalf("hook mode = %q", got)
			}
		})
	}
}

func tunUDPTestPacket(source, destination netip.AddrPort, payload []byte) []byte {
	udp := make([]byte, header.UDPMinimumSize+len(payload))
	header.UDP(udp).Encode(&header.UDPFields{SrcPort: source.Port(), DstPort: destination.Port(), Length: uint16(len(udp))})
	copy(udp[header.UDPMinimumSize:], payload)
	src := tcpip.AddrFromSlice(source.Addr().AsSlice())
	dst := tcpip.AddrFromSlice(destination.Addr().AsSlice())
	cs := ^checksum.Checksum(udp, header.PseudoHeaderChecksum(header.UDPProtocolNumber, src, dst, uint16(len(udp))))
	if cs == 0 {
		cs = 0xffff
	}
	header.UDP(udp).SetChecksum(cs)
	if source.Addr().Is4() {
		packet := make([]byte, header.IPv4MinimumSize+len(udp))
		ip := header.IPv4(packet)
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber), SrcAddr: src, DstAddr: dst})
		ip.SetChecksum(^ip.CalculateChecksum())
		copy(packet[header.IPv4MinimumSize:], udp)
		return packet
	}
	packet := make([]byte, header.IPv6MinimumSize+len(udp))
	header.IPv6(packet).Encode(&header.IPv6Fields{PayloadLength: uint16(len(udp)), HopLimit: 64, TransportProtocol: header.UDPProtocolNumber, SrcAddr: src, DstAddr: dst})
	copy(packet[header.IPv6MinimumSize:], udp)
	return packet
}

func tunTCPPeer(t *testing.T, instance *Instance, device *tuntest.ChannelTUN, source, destination netip.AddrPort) net.Conn {
	t.Helper()
	client := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true}),
			ipv6.NewProtocolWithOptions(ipv6.Options{AllowExternalLoopbackTraffic: true}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	link := channel.New(256, 1420, "")
	t.Cleanup(func() { link.Close(); client.Destroy() })
	if err := client.CreateNIC(1, link); err != nil {
		t.Fatal(err)
	}
	protocol := header.IPv4ProtocolNumber
	if source.Addr().Is6() {
		protocol = header.IPv6ProtocolNumber
	}
	if err := client.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: tcpip.AddrFromSlice(source.Addr().AsSlice()).WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	client.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	t.Cleanup(func() { cancel(); _ = instance.Stop(); workers.Wait() })
	workers.Go(func() {
		for {
			packet := link.ReadContext(ctx)
			if packet == nil {
				return
			}
			data := packet.ToBuffer()
			bytes := append([]byte(nil), data.Flatten()...)
			data.Release()
			packet.DecRef()
			select {
			case device.Outbound <- bytes:
			case <-ctx.Done():
				return
			}
		}
	})
	workers.Go(func() {
		for {
			select {
			case data, ok := <-device.Inbound:
				if !ok {
					return
				}
				packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
				link.InjectInbound(protocol, packet)
				packet.DecRef()
			case <-ctx.Done():
				return
			}
		}
	})
	dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialCancel()
	peer, err := gonet.DialContextTCP(dialCtx, client, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(destination.Addr().AsSlice()), Port: destination.Port()}, protocol)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if err := peer.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return peer
}

func TestTunModeTCPHTTPOrigin(t *testing.T) {
	tests := map[string]struct {
		network, host, source string
		http                  bool
	}{
		"IPv4 TCP origin":  {network: "tcp4", host: "127.0.0.1", source: "10.0.0.1:12345"},
		"IPv6 TCP origin":  {network: "tcp6", host: "::1", source: "[fd00::1]:12345"},
		"IPv4 HTTP origin": {network: "tcp4", host: "127.0.0.1", source: "10.0.0.1:12345", http: true},
		"IPv6 HTTP origin": {network: "tcp6", host: "::1", source: "[fd00::1]:12345", http: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { goleak.VerifyNone(t) })
			cfg, m, hooks := fixture(t)
			if err := m.Options.Add(t.Context(), "connection_strategy", options.TypeStr, "lazy", "When to establish origin connections."); err != nil {
				t.Fatal(err)
			}
			if err := m.Addons.Add(t.Context(), nextlayer.New(m.Options)); err != nil {
				t.Fatal(err)
			}
			instance := makeInstance(t, "tun", cfg)
			device := tuntest.NewChannelTUN()
			instance.openTun = func(_ string, _ *slog.Logger) (wgtun.Device, error) { return device.TUN(), nil }
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = instance.Stop() })
			origin, err := net.Listen(tt.network, net.JoinHostPort(tt.host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			var origins sync.WaitGroup
			t.Cleanup(func() { _ = origin.Close(); origins.Wait() })
			origins.Go(func() {
				if tt.http {
					server := &http.Server{ReadHeaderTimeout: 30 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path != "/tun" {
							t.Errorf("origin HTTP path = %q", r.URL.Path)
						}
						_, _ = io.WriteString(w, "tun-http")
					})}
					defer func() { _ = server.Close() }()
					if err := server.Serve(origin); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
						t.Errorf("HTTP origin: %v", err)
					}
					return
				}
				conn, err := origin.Accept()
				if err != nil {
					t.Errorf("TCP origin accept: %v", err)
					return
				}
				defer func() { _ = conn.Close() }()
				if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
					t.Error(err)
					return
				}
				payload := make([]byte, len("tun-tcp"))
				if _, err := io.ReadFull(conn, payload); err != nil || string(payload) != "tun-tcp" {
					t.Errorf("origin TCP request = %q, %v", payload, err)
					return
				}
				if _, err := conn.Write(payload); err != nil {
					t.Error(err)
				}
			})
			if tt.http {
				for _, option := range []struct {
					name  string
					typ   options.Type
					value any
				}{
					{"body_size_limit", options.TypeOptStr, nil},
					{"stream_large_bodies", options.TypeOptStr, nil},
					{"store_streamed_bodies", options.TypeBool, false},
					{"normalize_outbound_headers", options.TypeBool, true},
					{"keep_host_header", options.TypeBool, false},
				} {
					if err := m.Options.Add(t.Context(), option.name, option.typ, option.value, "HTTP proxy option."); err != nil {
						t.Fatal(err)
					}
				}
			}
			peer := tunTCPPeer(t, instance, device, netip.MustParseAddrPort(tt.source), origin.Addr().(*net.TCPAddr).AddrPort())
			if tt.http {
				if _, err := io.WriteString(peer, "GET /tun HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(peer), nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != http.StatusOK || string(body) != "tun-http" {
					t.Fatalf("HTTP response = %q, status=%d, %v", body, response.StatusCode, err)
				}
			} else {
				if _, err := io.WriteString(peer, "tun-tcp"); err != nil {
					t.Fatal(err)
				}
				payload := make([]byte, len("tun-tcp"))
				if _, err := io.ReadFull(peer, payload); err != nil || string(payload) != "tun-tcp" {
					t.Fatalf("TCP response = %q, %v", payload, err)
				}
			}
			if got := await(t, hooks.connected); got != "tun" {
				t.Fatalf("hook mode = %q", got)
			}
		})
	}
}

func TestTunExecutableUnsupportedPlatform(t *testing.T) {
	if runtime.GOOS == "linux" {
		return
	}
	tests := map[string]struct{}{"tun": {}}
	for spec := range tests {
		t.Run(spec, func(t *testing.T) {
			root, err := filepath.Abs("../../..")
			if err != nil {
				t.Fatal(err)
			}
			name := "mitmdump"
			if runtime.GOOS == "windows" {
				name += ".exe"
			}
			binary := filepath.Join(t.TempDir(), name)
			buildCtx, buildCancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer buildCancel()
			build := exec.CommandContext(buildCtx, "go", "build", "-o", binary, "./cmd/mitmdump")
			build.Dir = root
			if output, err := build.CombinedOutput(); err != nil {
				t.Fatalf("building CLI: %v\n%s", err, output)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary, "--mode", spec, "--set", "confdir="+t.TempDir())
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || ctx.Err() != nil || !strings.Contains(string(output), "TUN proxy mode is only supported on Linux") {
				t.Fatalf("CLI native availability error = %v\n%s", err, output)
			}
		})
	}
}

func TestTunUnsupportedPlatform(t *testing.T) {
	if runtime.GOOS == "linux" {
		return
	}
	tests := map[string]struct{}{"tun": {}, "tun:utun4": {}}
	for spec := range tests {
		t.Run(spec, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			mode, err := modespec.Parse(spec)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := New(mode, cfg)
			if err != nil {
				t.Fatal(err)
			}
			err = instance.Start(t.Context())
			if err == nil || err.Error() != "TUN proxy mode is only supported on Linux" {
				t.Fatalf("Start = %v", err)
			}
			if instance.IsRunning() || len(instance.ListenAddrs()) != 0 || instance.LastError() != err {
				t.Fatal("unsupported native startup state")
			}
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
