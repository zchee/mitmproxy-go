// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
)

func syntheticMacOSFlowPeer(t *testing.T, r *macOSRedirector, flow *NewFlow) *net.UnixConn {
	t.Helper()
	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: r.socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := writeIPC(peer, flow); err != nil {
		t.Fatal(err)
	}
	return peer
}

// These peers encode synthetic contract vectors; they are not native captures.
func TestMacOSStreams(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("synthetic starter uses a Unix shell and Unix sockets")
	}
	root := t.TempDir()
	tests := map[string]struct {
		tcp bool
	}{
		"success: TCP handshake preserves raw bytes":          {tcp: true},
		"success: UDP boundaries empty packets and deadlines": {},
	}
	index := 0
	for name, test := range tests {
		index++
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, strconv.Itoa(index))
			r := NewMacOSRedirector(dir, syntheticMacOSStarter(t, dir, false)).(*macOSRedirector)
			r.socketPath = filepath.Join(dir, "s")
			t.Cleanup(func() { _ = r.Close() })
			_ = syntheticMacOSPeer(t, r, t.Context())
			pid, process := uint32(123), "synthetic-curl"
			tunnel := &TunnelInfo{Pid: &pid, ProcessName: &process}
			remote := &Address{Host: "127.0.0.1", Port: 443}
			if test.tcp {
				flow := &TcpFlow{RemoteAddress: remote, TunnelInfo: tunnel}
				peer := syntheticMacOSFlowPeer(t, r, &NewFlow{Message: &NewFlow_Tcp{Tcp: flow}})
				if _, err := peer.Write([]byte("raw TCP tail")); err != nil {
					t.Fatal(err)
				}
				conn, got, err := r.AcceptTCP(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if !proto.Equal(got, flow) {
					t.Fatalf("TCP metadata = %v, want %v", got, flow)
				}
				data := make([]byte, len("raw TCP tail"))
				if _, err := io.ReadFull(conn, data); err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff([]byte("raw TCP tail"), data); diff != "" {
					t.Fatal(diff)
				}
				if err := conn.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				flow := &UdpFlow{LocalAddress: &Address{Host: "127.0.0.1", Port: 12345}, TunnelInfo: tunnel}
				peer := syntheticMacOSFlowPeer(t, r, &NewFlow{Message: &NewFlow_Udp{Udp: flow}})
				if err := writeIPC(peer, &UdpPacket{RemoteAddress: remote}); err != nil {
					t.Fatal(err)
				}
				conn, got, err := r.AcceptUDP(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = conn.Close() }()
				if !proto.Equal(got, flow) || conn.LocalAddr().String() != "127.0.0.1:12345" || conn.RemoteAddr().String() != "127.0.0.1:443" {
					t.Fatalf("UDP tuple metadata = %v, %v, %v", got, conn.LocalAddr(), conn.RemoteAddr())
				}
				buf := make([]byte, 3)
				if n, addr, err := conn.ReadFrom(buf); n != 0 || err != nil || addr.String() != conn.RemoteAddr().String() {
					t.Fatalf("first empty packet = %d, %v, %v", n, addr, err)
				}
				for _, data := range []string{"longer", "next"} {
					if err := writeIPC(peer, &UdpPacket{Data: []byte(data), RemoteAddress: remote}); err != nil {
						t.Fatal(err)
					}
					if n, _, err := conn.ReadFrom(buf); n != 3 || err != nil || string(buf) != data[:3] {
						t.Fatalf("truncated packet = %d, %q, %v", n, buf, err)
					}
				}
				if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, _, err := conn.ReadFrom(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("expired read = %v", err)
				}
				if err := conn.SetReadDeadline(time.Time{}); err != nil {
					t.Fatal(err)
				}
				if n, err := conn.WriteTo([]byte("reply"), nil); err != nil || n != 5 {
					t.Fatalf("UDP reply = %d, %v", n, err)
				}
				var reply UdpPacket
				if err := readIPC(peer, &reply); err != nil || string(reply.GetData()) != "reply" || !proto.Equal(reply.RemoteAddress, remote) {
					t.Fatalf("reply frame = %v, %v", &reply, err)
				}
				if _, err := conn.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 444}); err == nil {
					t.Fatal("changed write destination accepted")
				}
				if cap(conn.(*macOSUDPTransport).packets) != 10 {
					t.Fatal("UDP packet queue differs from upstream bound")
				}
			}
			if err := r.SetIntercept(t.Context(), ""); err != nil {
				t.Fatalf("closing a flow closed the daemon: %v", err)
			}
		})
	}
}

func TestMacOSStreamLifetime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("synthetic starter uses a Unix shell and Unix sockets")
	}
	root := t.TempDir()
	tests := map[string]struct{ fullQueue bool }{
		"success: delayed UDP does not stall TCP": {},
		"success: close joins full UDP queue":     {fullQueue: true},
	}
	index := 0
	for name, test := range tests {
		index++
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, strconv.Itoa(index))
			r := NewMacOSRedirector(dir, syntheticMacOSStarter(t, dir, false)).(*macOSRedirector)
			r.socketPath = filepath.Join(dir, "s")
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			t.Cleanup(func() { _ = r.Close() })
			_ = syntheticMacOSPeer(t, r, ctx)
			flow := &UdpFlow{LocalAddress: &Address{Host: "127.0.0.1", Port: 12345}, TunnelInfo: new(TunnelInfo)}
			peer := syntheticMacOSFlowPeer(t, r, &NewFlow{Message: &NewFlow_Udp{Udp: flow}})
			if !test.fullQueue {
				canceled, stop := context.WithCancel(ctx)
				stop()
				if _, _, err := r.AcceptUDP(canceled); !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled accept = %v", err)
				}
				_ = syntheticMacOSFlowPeer(t, r, &NewFlow{Message: &NewFlow_Tcp{Tcp: &TcpFlow{RemoteAddress: &Address{Host: "example.test", Port: 443}}}})
				conn, _, err := r.AcceptTCP(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := conn.Close(); err != nil {
					t.Fatal(err)
				}
			}
			remote := &Address{Host: "127.0.0.1", Port: 443}
			packet := &UdpPacket{RemoteAddress: remote, Data: []byte("first")}
			if err := writeIPC(peer, packet); err != nil {
				t.Fatal(err)
			}
			transport, _, err := r.AcceptUDP(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if test.fullQueue {
				for range 10 {
					if err := writeIPC(peer, packet); err != nil {
						t.Fatal(err)
					}
				}
				udp := transport.(*macOSUDPTransport)
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				for len(udp.packets) != 10 {
					select {
					case <-ticker.C:
					case <-ctx.Done():
						t.Fatalf("UDP queue failed to fill: %v", ctx.Err())
					}
				}
				if len(udp.slots) != 10 {
					t.Fatal("UDP reader did not bound in-flight packet admission")
				}
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := transport.ReadFrom(make([]byte, 32)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("read after daemon close = %v", err)
			}
			if err := transport.Close(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := r.AcceptTCP(t.Context()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("accept after daemon close = %v", err)
			}
			r.mu.Lock()
			retained := len(r.streams)
			r.mu.Unlock()
			if retained != 0 || len(r.tcp) != 0 || len(r.udp) != 0 {
				t.Fatal("closed daemon retained stream admission state")
			}
		})
	}
}

func TestMacOSUDPDestination(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("synthetic starter uses a Unix shell and Unix sockets")
	}
	root := t.TempDir()
	tests := map[string]struct{ remote *Address }{
		"error: changed destination": {remote: &Address{Host: "127.0.0.1", Port: 444}},
		"error: missing destination": {},
		"error: invalid port":        {remote: &Address{Host: "127.0.0.1", Port: 65536}},
	}
	index := 0
	for name, test := range tests {
		index++
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, strconv.Itoa(index))
			r := NewMacOSRedirector(dir, syntheticMacOSStarter(t, dir, false)).(*macOSRedirector)
			r.socketPath = filepath.Join(dir, "s")
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			t.Cleanup(func() { _ = r.Close() })
			_ = syntheticMacOSPeer(t, r, ctx)
			flow := &UdpFlow{LocalAddress: &Address{Host: "127.0.0.1", Port: 12345}, TunnelInfo: new(TunnelInfo)}
			peer := syntheticMacOSFlowPeer(t, r, &NewFlow{Message: &NewFlow_Udp{Udp: flow}})
			if err := writeIPC(peer, &UdpPacket{RemoteAddress: &Address{Host: "127.0.0.1", Port: 443}}); err != nil {
				t.Fatal(err)
			}
			transport, _, err := r.AcceptUDP(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = transport.Close() }()
			if _, _, err := transport.ReadFrom(make([]byte, 1)); err != nil {
				t.Fatal(err)
			}
			if err := writeIPC(peer, &UdpPacket{RemoteAddress: test.remote}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-transport.Context().Done():
			case <-ctx.Done():
				t.Fatalf("invalid packet failed to close tuple: %v", ctx.Err())
			}
			if _, _, err := transport.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("invalid tuple read = %v", err)
			}
			if err := r.SetIntercept(ctx, ""); err != nil {
				t.Fatalf("invalid tuple closed daemon: %v", err)
			}
		})
	}
}

func TestMacOSBadFlow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("synthetic starter uses a Unix shell and Unix sockets")
	}
	root := t.TempDir()
	tests := map[string]struct{ flow *NewFlow }{
		"error: missing flow type":    {flow: new(NewFlow)},
		"error: missing TCP address":  {flow: &NewFlow{Message: &NewFlow_Tcp{Tcp: new(TcpFlow)}}},
		"error: missing UDP metadata": {flow: &NewFlow{Message: &NewFlow_Udp{Udp: new(UdpFlow)}}},
	}
	index := 0
	for name, test := range tests {
		index++
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, strconv.Itoa(index))
			r := NewMacOSRedirector(dir, syntheticMacOSStarter(t, dir, false)).(*macOSRedirector)
			r.socketPath = filepath.Join(dir, "s")
			t.Cleanup(func() { _ = r.Close() })
			_ = syntheticMacOSPeer(t, r, t.Context())
			_ = syntheticMacOSFlowPeer(t, r, test.flow)
			if _, _, err := r.AcceptTCP(t.Context()); err == nil {
				t.Fatal("invalid flow admitted")
			}
			if err := r.SetIntercept(t.Context(), ""); err != nil {
				t.Fatalf("invalid flow poisoned control: %v", err)
			}
		})
	}
}
