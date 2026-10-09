// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/local"
	"github.com/zchee/mitmproxy-go/options"
)

func localIPCWrite(t *testing.T, peer net.Conn, message proto.Message) {
	t.Helper()
	payload, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(payload)))
	if _, err := io.Copy(peer, bytes.NewReader(prefix[:])); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(peer, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
}

type localDestinationObserver struct {
	destinations chan connection.Address
}

func (o *localDestinationObserver) NextLayer(_ context.Context, value *hookdata.NextLayer) error {
	if value.Context.Server.Address == nil {
		return errors.New("local destination missing before next-layer hook")
	}
	select {
	case o.destinations <- *value.Context.Server.Address:
	default:
	}
	return nil
}

// TestLocalIPCOrigins is a preservation row for native IPC origin delivery.
func TestLocalIPCOrigins(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}
	tests := map[string]struct{ udp bool }{"TCP real origin": {}, "UDP real origin": {udp: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			redirector, control := localIPCFixture(t)
			cfg, m, hooks := fixture(t)
			if err := m.Options.Add(t.Context(), "connection_strategy", options.TypeStr, "lazy", "When to establish origin connections."); err != nil {
				t.Fatal(err)
			}
			observer := &localDestinationObserver{destinations: make(chan connection.Address, 8)}
			if err := m.Addons.Add(t.Context(), observer); err != nil {
				t.Fatal(err)
			}
			if err := m.Addons.Add(t.Context(), nextlayer.New(m.Options)); err != nil {
				t.Fatal(err)
			}
			var expected connection.Address
			var admittedMode string
			instance := localIPCMode(t, cfg, redirector, "local")
			t.Cleanup(func() { _ = instance.Stop() })
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			localIPCRead(t, control, new(local.InterceptConf))
			peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: "/tmp/mitmproxy-" + strconv.Itoa(os.Getpid()), Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = peer.Close() })
			if err := peer.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			tunnel := &local.TunnelInfo{Pid: new(uint32(42)), ProcessName: new("curl")}
			if tt.udp {
				origin, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = origin.Close() }()
				delivered := make(chan struct {
					data   []byte
					client net.Addr
					err    error
				}, 1)
				go func() {
					data := make([]byte, 64)
					n, client, err := origin.ReadFrom(data)
					delivered <- struct {
						data   []byte
						client net.Addr
						err    error
					}{data[:n], client, err}
				}()
				progress := func() string {
					return fmt.Sprintf("admitted=%t; pending destination hooks=%d origin deliveries=%d", admittedMode != "", len(observer.destinations), len(delivered))
				}
				destination := origin.LocalAddr().(*net.UDPAddr)
				expected = connection.Address{Host: destination.IP.String(), Port: destination.Port}
				address := &local.Address{Host: destination.IP.String(), Port: uint32(destination.Port)}
				localIPCWrite(t, peer, &local.NewFlow{Message: &local.NewFlow_Udp{Udp: &local.UdpFlow{LocalAddress: &local.Address{Host: "10.0.0.1", Port: 4242}, TunnelInfo: tunnel}}})
				localIPCWrite(t, peer, &local.UdpPacket{RemoteAddress: address, Data: []byte("local-udp")})
				admittedMode = awaitFixtureSignal(t, hooks.connected, "local UDP tuple admission", progress)
				result := awaitFixtureSignal(t, delivered, "local UDP origin datagram delivery", progress)
				if result.err != nil || string(result.data) != "local-udp" {
					stack := make([]byte, 1<<20)
					t.Fatalf("UDP origin = %q, %v; %s\n%s", result.data, result.err, progress(), stack[:runtime.Stack(stack, true)])
				}
				if _, err := origin.WriteTo(result.data, result.client); err != nil {
					t.Fatal(err)
				}
				var reply local.UdpPacket
				localIPCRead(t, peer, &reply)
				if string(reply.Data) != "local-udp" || reply.RemoteAddress.GetPort() != address.Port {
					t.Fatalf("UDP IPC reply = %q, %v", reply.Data, reply.RemoteAddress)
				}
			} else {
				origin, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = origin.Close() }()
				if err := origin.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
					t.Fatal(err)
				}
				destination := origin.Addr().(*net.TCPAddr)
				expected = connection.Address{Host: destination.IP.String(), Port: destination.Port}
				localIPCWrite(t, peer, &local.NewFlow{Message: &local.NewFlow_Tcp{Tcp: &local.TcpFlow{RemoteAddress: &local.Address{Host: destination.IP.String(), Port: uint32(destination.Port)}, TunnelInfo: tunnel}}})
				if _, err := io.WriteString(peer, "local-tcp"); err != nil {
					t.Fatal(err)
				}
				if err := peer.CloseWrite(); err != nil {
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
				data := make([]byte, len("local-tcp"))
				if _, err := io.ReadFull(conn, data); err != nil || string(data) != "local-tcp" {
					t.Fatalf("TCP origin = %q, %v", data, err)
				}
				if _, err := conn.Write(data); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(peer, data); err != nil || string(data) != "local-tcp" {
					t.Fatalf("TCP IPC reply = %q, %v", data, err)
				}
			}
			if got := await(t, observer.destinations); got != expected {
				t.Fatalf("destination before next-layer hook = %v, want %v", got, expected)
			}
			if admittedMode == "" {
				admittedMode = await(t, hooks.connected)
			}
			if admittedMode != "local" {
				t.Fatalf("hook mode = %q", admittedMode)
			}
		})
	}
}
