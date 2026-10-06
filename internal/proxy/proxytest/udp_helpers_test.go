// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest_test

import (
	"bytes"
	"encoding/pem"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func TestUDPEchoOrigin(t *testing.T) {
	tests := map[string]struct{ payload []byte }{
		"success: empty datagram":          {payload: []byte{}},
		"success: text datagram":           {payload: []byte("echo")},
		"success: binary datagram":         {payload: []byte{0, 0xff, '\n', 0}},
		"success: multi-kilobyte datagram": {payload: bytes.Repeat([]byte{0xa5}, 8192)},
	}
	for name, test := range tests {
		var addr string
		t.Run(name, func(t *testing.T) {
			origin := proxytest.StartUDPEchoOrigin(t)
			addr = origin.Addr
			client, err := (&net.Dialer{}).DialContext(t.Context(), "udp4", origin.Addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			for _, payload := range [][]byte{test.payload, []byte("next datagram")} {
				if n, err := client.Write(payload); err != nil || n != len(payload) {
					t.Fatalf("write=%d, %v; want %d", n, err, len(payload))
				}
				buf := make([]byte, layer.MaxUDPPacketBytes)
				n, err := client.Read(buf)
				if err != nil {
					stacks := make([]byte, 1<<20)
					t.Fatalf("UDP echo read: %v\n%s", err, stacks[:runtime.Stack(stacks, true)])
				}
				if diff := gocmp.Diff(payload, buf[:n]); diff != "" {
					t.Fatalf("datagram (-want +got):\n%s", diff)
				}
			}
		})
		if addr == "" {
			continue
		}
		conn, err := net.ListenPacket("udp4", addr)
		if err != nil {
			t.Fatalf("UDP origin cleanup did not release %q: %v", addr, err)
		}
		_ = conn.Close()
	}
}

func TestReverseDTLSHelper(t *testing.T) {
	tests := map[string]struct{ trusted bool }{
		"success: origin without a CA": {},
		"success: trusted origin CA":   {trusted: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			origin := proxytest.StartUDPEchoOrigin(t)
			if test.trusted {
				origin.CA = proxytest.StartTLSOrigin(t, []string{"127.0.0.1"}, nil).CA
			}
			p := proxytest.StartReverseDTLS(t, origin, proxytest.WithOptions(map[string]any{"ssl_insecure": true}))
			if diff := gocmp.Diff([]string{"reverse:dtls://" + origin.Addr + "@127.0.0.1:0"}, p.Master.Options.Seq("mode")); diff != "" {
				t.Fatalf("reverse mode (-want +got):\n%s", diff)
			}
			host, _, err := net.SplitHostPort(p.Addr)
			if err != nil || host != "127.0.0.1" {
				t.Fatalf("listener=%q, %v; want IPv4 loopback", p.Addr, err)
			}
			if !p.Master.Options.Bool("ssl_insecure") {
				t.Fatal("caller options were not applied")
			}
			if !test.trusted {
				return
			}
			path := p.Master.Options.OptStr("ssl_verify_upstream_trusted_ca")
			if path == nil {
				t.Fatal("origin CA was not trusted")
			}
			raw, err := os.ReadFile(*path)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(raw)
			if block == nil {
				t.Fatal("origin trust bundle is not PEM")
			}
			if diff := gocmp.Diff(origin.CA.Raw, block.Bytes); diff != "" {
				t.Fatalf("trusted origin CA (-want +got):\n%s", diff)
			}
		})
	}
}
