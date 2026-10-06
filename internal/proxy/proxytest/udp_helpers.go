// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest

import (
	"errors"
	"net"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// StartUDPEchoOrigin starts a UDP4 origin on an ephemeral loopback port. Each
// received datagram, including an empty one, is echoed to its sender. Cleanup
// closes the socket and joins the reader before returning.
func StartUDPEchoOrigin(t testing.TB) *Origin {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, layer.MaxUDPPacketBytes)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("proxytest: UDP origin read: %v", err)
				}
				return
			}
			if _, err := conn.WriteTo(buf[:n], peer); err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("proxytest: UDP origin write: %v", err)
				}
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = conn.Close()
		wait(t, done, "UDP origin shutdown")
	})
	return &Origin{Addr: conn.LocalAddr().String()}
}

// StartReverseDTLS starts a reverse DTLS proxy on an ephemeral IPv4 loopback
// port, trusting origin's CA when present. Caller options are applied after
// these defaults. A nil origin fails the test before starting a listener.
func StartReverseDTLS(t testing.TB, origin *Origin, opts ...Option) *Proxy {
	t.Helper()
	if origin == nil || origin.Addr == "" {
		t.Fatal("proxytest: StartReverseDTLS requires an origin address")
	}
	defaults := []Option{WithOptions(map[string]any{"mode": []string{"reverse:dtls://" + origin.Addr + "@127.0.0.1:0"}})}
	if origin.CA != nil {
		defaults = append(defaults, WithTrustedCA(origin.CA))
	}
	return Start(t, append(defaults, opts...)...)
}
