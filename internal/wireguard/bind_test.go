// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.zx2c4.com/wireguard/conn"
)

func TestSocketBind(t *testing.T) {
	tests := map[string]struct{ host string }{
		"success: IPv4 host": {host: "127.0.0.1"},
		"success: IPv6 host": {host: "::1"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			socket, err := net.ListenPacket("udp", net.JoinHostPort(test.host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = socket.Close() }()
			bind := &socketBind{socket: socket}
			// Device.Up calls BindClose before the first Bind.Open.
			if err := bind.Close(); err != nil {
				t.Fatalf("initial BindClose: %v", err)
			}
			receivers, port, err := bind.Open(0)
			if err != nil {
				t.Fatal(err)
			}
			if port == 0 || int(port) != socket.LocalAddr().(*net.UDPAddr).Port {
				t.Errorf("reported port %d differs from bound listener", port)
			}
			if len(receivers) != 1 || bind.BatchSize() != 1 {
				t.Fatal("single-packet bind returned an inconsistent receive batch")
			}
			peer, err := net.ListenPacket("udp", net.JoinHostPort(test.host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			deadline, _ := ctx.Deadline()
			if err := socket.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := peer.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			const incoming = "client datagram"
			if _, err := peer.WriteTo([]byte(incoming), socket.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			packets := [][]byte{make([]byte, 256)}
			sizes := make([]int, 1)
			endpoints := make([]conn.Endpoint, 1)
			if count, err := receivers[0](packets, sizes, endpoints); err != nil || count != 1 {
				t.Fatalf("receive count=%d, err=%v", count, err)
			}
			if diff := gocmp.Diff(incoming, string(packets[0][:sizes[0]])); diff != "" {
				t.Errorf("incoming datagram (-want +got):\n%s", diff)
			}
			if endpoints[0].DstToString() != peer.LocalAddr().String() {
				t.Error("peer endpoint differs from the datagram sender")
			}
			const outgoing = "server datagram"
			if err := bind.Send([][]byte{[]byte(outgoing)}, endpoints[0]); err != nil {
				t.Fatal(err)
			}
			var reply [256]byte
			n, from, err := peer.ReadFrom(reply[:])
			if err != nil {
				t.Fatal(err)
			}
			if from.String() != socket.LocalAddr().String() {
				t.Error("server reply came from a different listener")
			}
			if diff := gocmp.Diff(outgoing, string(reply[:n])); diff != "" {
				t.Errorf("outgoing datagram (-want +got):\n%s", diff)
			}
			closed := make(chan error, 1)
			go func() { _, err := receivers[0](packets, sizes, endpoints); closed <- err }()
			if err := bind.Close(); err != nil {
				t.Fatal(err)
			}
			if err := bind.Close(); err != nil {
				t.Fatalf("repeated Close: %v", err)
			}
			select {
			case err := <-closed:
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("blocked receive error=%v, want net.ErrClosed", err)
				}
			case <-ctx.Done():
				deviceTestTimeout(t, ctx)
			}
			if _, _, err := bind.Open(0); !errors.Is(err, net.ErrClosed) {
				t.Errorf("reopened consumed socket error=%v, want net.ErrClosed", err)
			}
		})
	}
}

func TestSocketBindEndpoint(t *testing.T) {
	tests := map[string]struct {
		text    string
		invalid bool
	}{
		"success: IPv4":          {text: "127.0.0.1:51820"},
		"success: IPv6":          {text: "[::1]:51820"},
		"error: absent port":     {text: "127.0.0.1", invalid: true},
		"error: invalid address": {text: "example.test:51820", invalid: true},
		"error: invalid port":    {text: "127.0.0.1:65536", invalid: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			bind := &socketBind{}
			endpoint, err := bind.ParseEndpoint(test.text)
			if test.invalid {
				if err == nil {
					t.Fatal("invalid numeric endpoint accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if endpoint.DstToString() != test.text {
				t.Errorf("parsed endpoint=%s, want %s", endpoint.DstToString(), test.text)
			}
		})
	}
}
