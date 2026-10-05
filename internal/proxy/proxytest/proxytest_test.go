// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestReverseTCP(t *testing.T) {
	origin := proxytest.StartEchoOrigin(t)
	p := proxytest.Start(t, proxytest.WithOptions(map[string]any{"mode": []string{"reverse:tcp://" + origin.Addr}}))
	client := dial(t, p.Addr)
	exchange(t, client, "through the proxy")
	if p.Server.ActiveConnections(t.Context()) != 1 {
		t.Fatal("client connection not registered")
	}
	_ = client.Close()
	awaitHook(t, p, "tcp_end")
	if !slices.Contains(p.Recorder.Hooks(), "tcp_start") {
		t.Fatalf("hooks = %v", p.Recorder.Hooks())
	}
}

func TestDotTestOriginMapping(t *testing.T) {
	origin := proxytest.StartTLSOrigin(t, []string{"example.test"}, nil)
	p := proxytest.Start(t,
		proxytest.WithOrigin("EXAMPLE.test.", origin),
		proxytest.WithTrustedCA(origin.CA),
		proxytest.WithOptions(map[string]any{"mode": []string{"reverse:tls://example.test:443"}}),
	)
	raw := dial(t, p.Addr)
	client := tls.Client(raw, &tls.Config{RootCAs: p.CAPool, ServerName: "example.test"})
	if err := client.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	leaf := client.ConnectionState().PeerCertificates[0]
	if err := leaf.VerifyHostname("example.test"); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(origin.Leaf.DNSNames, leaf.DNSNames); diff != "" {
		t.Fatal(diff)
	}
	exchange(t, client, "tls through two handshakes")
	_ = client.Close()
	awaitHook(t, p, "tcp_end")
}

func TestUnmappedDotTestFails(t *testing.T) {
	p := proxytest.Start(t, proxytest.WithOptions(map[string]any{"mode": []string{"reverse:tcp://missing.test:443"}}))
	client := dial(t, p.Addr)
	if _, err := io.WriteString(client, "hello"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("unmapped .test origin served data")
	}
	awaitHook(t, p, "server_connect_error")
}

func TestProxyCertificateAuthority(t *testing.T) {
	p := proxytest.Start(t, proxytest.WithOptions(map[string]any{"server": false}))
	if p.CA == nil || !p.CA.IsCA {
		t.Fatalf("CA = %+v", p.CA)
	}
	if p.ConfDir == "" || p.Master == nil || p.Recorder == nil {
		t.Fatal("incomplete harness surface")
	}
	if _, err := p.CA.Verify(x509.VerifyOptions{Roots: p.CAPool}); err != nil {
		t.Fatal(err)
	}
}

func dial(t *testing.T, address string) net.Conn {
	t.Helper()
	client, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func exchange(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(payload, string(buf)); diff != "" {
		t.Fatal(diff)
	}
}

func awaitHook(t *testing.T, p *proxytest.Proxy, hook string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !slices.Contains(p.Recorder.Hooks(), hook) {
		if time.Now().After(deadline) {
			t.Fatalf("hook %q never fired; got %v", hook, p.Recorder.Hooks())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
