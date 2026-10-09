// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func TestTLSOriginCertificateAndServerFirst(t *testing.T) {
	origin := proxytest.StartTLSOrigin(t, []string{"example.test", "www.example.test", "127.0.0.1"}, nil)
	p := proxytest.Start(t,
		proxytest.WithOrigin("example.test", origin),
		proxytest.WithOptions(map[string]any{
			"mode":           []string{"reverse:tls://example.test:443"},
			"ciphers_client": new("ECDHE-RSA-AES128-GCM-SHA256"),
		}),
	)
	client := tls.Client(dial(t, p.Addr), &tls.Config{
		RootCAs: p.CAPool, ServerName: "example.test",
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	})
	if err := client.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	exchange(t, client, "server certificate is available before interception")
	leaf := client.ConnectionState().PeerCertificates[0]
	if diff := gocmp.Diff(origin.Leaf.DNSNames, leaf.DNSNames); diff != "" {
		t.Fatalf("intercepted DNS SANs (-origin +proxy):\n%s", diff)
	}
	if diff := gocmp.Diff(origin.Leaf.IPAddresses, leaf.IPAddresses); diff != "" {
		t.Fatalf("intercepted IP SANs (-origin +proxy):\n%s", diff)
	}
	hooks := p.Recorder.Hooks()
	serverEstablished, clientStarted := slices.Index(hooks, "tls_established_server"), slices.Index(hooks, "tls_start_client")
	if serverEstablished < 0 || clientStarted <= serverEstablished {
		t.Fatalf("server TLS must precede client TLS; hooks = %v", hooks)
	}
	var cipher string
	if err := p.Master.Do(t.Context(), func(context.Context) error {
		for _, call := range p.Recorder.Calls() {
			if call.Hook == "tls_established_client" {
				if value := call.Arg.(*hookdata.TLS).Conn.Cipher; value != nil {
					cipher = *value
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff("ECDHE-RSA-AES128-GCM-SHA256", cipher); diff != "" {
		t.Fatalf("OpenSSL client cipher name (-want +got):\n%s", diff)
	}
}

func TestIgnoreHostsReplaysTLS(t *testing.T) {
	origin := proxytest.StartTLSOrigin(t, []string{"example.test"}, nil)
	p := proxytest.Start(t,
		proxytest.WithOrigin("example.test", origin),
		proxytest.WithOptions(map[string]any{
			"mode":         []string{"reverse:tls://example.test:443"},
			"ignore_hosts": []string{`^example\.test:443$`},
		}),
	)
	roots := x509.NewCertPool()
	roots.AddCert(origin.CA)
	client := tls.Client(dial(t, p.Addr), &tls.Config{RootCAs: roots, ServerName: "example.test"})
	if err := client.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(origin.Leaf.Raw, client.ConnectionState().PeerCertificates[0].Raw); diff != "" {
		t.Fatalf("ignored connection did not serve the original certificate:\n%s", diff)
	}
	exchange(t, client, "encrypted payload survives the raw tunnel")
	for _, name := range p.Recorder.Hooks() {
		if strings.HasPrefix(name, "tls_start_") || strings.HasPrefix(name, "tls_established_") {
			t.Fatalf("ignored connection was intercepted: hooks = %v", p.Recorder.Hooks())
		}
	}
}

func TestOriginTLSFailures(t *testing.T) {
	tests := map[string]struct {
		names []string
		trust bool
		want  string
	}{
		"error: untrusted origin":      {names: []string{"example.test"}, want: "unknown authority"},
		"error: wrong origin hostname": {names: []string{"other.test"}, trust: true, want: "not example.test"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			origin := proxytest.StartTLSOrigin(t, tt.names, nil)
			mapped := &proxytest.Origin{Addr: origin.Addr}
			if tt.trust {
				mapped.CA = origin.CA
			}
			failed := &tlsFailures{server: make(chan string, 1)}
			p := proxytest.Start(t,
				proxytest.WithOrigin("example.test", mapped),
				proxytest.WithAddons(failed),
				proxytest.WithOptions(map[string]any{"mode": []string{"reverse:tls://example.test:443"}}),
			)
			client := tls.Client(dial(t, p.Addr), &tls.Config{RootCAs: p.CAPool, ServerName: "example.test"})
			// Upstream TLS failure still permits client TLS, so the proxy can
			// report the origin failure over the established client session.
			if err := client.HandshakeContext(t.Context()); err != nil {
				t.Fatalf("client TLS after origin failure: %v", err)
			}
			message := receive(t, failed.server, testEvent{name: "tls_failed_server", arrived: p.Recorder.Hooks})
			if !strings.Contains(message, tt.want) {
				t.Fatalf("tls_failed_server error = %q, want substring %q", message, tt.want)
			}
			if slices.Contains(p.Recorder.Hooks(), "tls_established_server") {
				t.Fatalf("failed origin marked established: %v", p.Recorder.Hooks())
			}
		})
	}
}

func TestClientTLSFailure(t *testing.T) {
	origin := proxytest.StartTLSOrigin(t, []string{"example.test"}, nil)
	failed := &tlsFailures{client: make(chan string, 1)}
	p := proxytest.Start(t,
		proxytest.WithOrigin("example.test", origin),
		proxytest.WithAddons(failed),
		proxytest.WithOptions(map[string]any{"mode": []string{"reverse:tls://example.test:443"}}),
	)
	client := tls.Client(dial(t, p.Addr), &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "example.test"})
	if err := client.HandshakeContext(t.Context()); err == nil {
		t.Fatal("client trusted the proxy without its CA")
	}
	if message := receive(t, failed.client, testEvent{name: "tls_failed_client", arrived: p.Recorder.Hooks}); message == "" {
		t.Fatal("tls_failed_client did not publish its error")
	}
}

type tlsFailures struct {
	client chan string
	server chan string
}

func (f *tlsFailures) TLSFailedClient(_ context.Context, data *hookdata.TLS) error {
	if f.client != nil && data.Conn.Error != nil {
		f.client <- *data.Conn.Error
	}
	return nil
}

func (f *tlsFailures) TLSFailedServer(_ context.Context, data *hookdata.TLS) error {
	if f.server != nil && data.Conn.Error != nil {
		f.server <- *data.Conn.Error
	}
	return nil
}

type testEvent struct {
	name    string
	arrived func() []string
}

func receive[T any](t *testing.T, ch <-chan T, events ...testEvent) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(30 * time.Second):
		name := t.Name()
		var arrived []string
		if len(events) > 0 {
			name = events[0].name
			if events[0].arrived != nil {
				arrived = events[0].arrived()
			}
		}
		buf := make([]byte, 1<<20)
		t.Fatalf("waiting for test event %q hung; arrived hooks=%v\n%s", name, arrived, buf[:runtime.Stack(buf, true)])
		var zero T
		return zero
	}
}

func TestOriginCleanupClosesActiveConnections(t *testing.T) {
	var client net.Conn
	t.Run("active origin connection", func(t *testing.T) {
		origin := proxytest.StartEchoOrigin(t)
		var err error
		client, err = (&net.Dialer{}).DialContext(t.Context(), "tcp", origin.Addr)
		if err != nil {
			t.Fatal(err)
		}
		exchange(t, client, "the origin must close this socket at cleanup")
	})
	if client == nil {
		t.Fatal("origin client was not established")
	}
	defer func() { _ = client.Close() }()
	if err := client.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("origin cleanup read = %v, want EOF", err)
	}
}
