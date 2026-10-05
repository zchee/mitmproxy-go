// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func TestRegularAndSecureProxyTLS(t *testing.T) {
	tests := map[string]struct{ secureProxy bool }{
		"success: regular CONNECT":          {},
		"success: secure web proxy CONNECT": {secureProxy: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			origin, offers := startALPNOrigin(t)
			p := proxytest.Start(t, proxytest.WithOrigin("example.test", origin))
			conn := dial(t, p.Addr)
			if tt.secureProxy {
				outer := tls.Client(conn, &tls.Config{RootCAs: p.CAPool, ServerName: "proxy.test", NextProtos: []string{"h2", "http/1.1"}})
				if err := outer.HandshakeContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				if got := outer.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
					t.Fatalf("secure proxy ALPN = %q, want http/1.1", got)
				}
				conn = outer
			}
			connectTunnel(t, conn, "example.test:443")
			client := tls.Client(conn, &tls.Config{RootCAs: p.CAPool, ServerName: "example.test", NextProtos: []string{"h2", "http/1.1"}})
			if err := client.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			state := client.ConnectionState()
			if diff := gocmp.Diff("http/1.1", state.NegotiatedProtocol); diff != "" {
				t.Fatalf("client ALPN (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff([]string{"http/1.1"}, receive(t, offers)); diff != "" {
				t.Fatalf("origin ALPN offers (-want +got):\n%s", diff)
			}
			leaf := state.PeerCertificates[0]
			if diff := gocmp.Diff(origin.Leaf.DNSNames, leaf.DNSNames); diff != "" {
				t.Fatalf("DNS SANs (-origin +proxy):\n%s", diff)
			}
			if diff := gocmp.Diff(origin.Leaf.IPAddresses, leaf.IPAddresses); diff != "" {
				t.Fatalf("IP SANs (-origin +proxy):\n%s", diff)
			}
			response, body := httpExchange(t, client, "GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\n")
			if response.StatusCode != http.StatusOK || string(body) != "secure origin" {
				t.Fatalf("HTTPS response = %d %q", response.StatusCode, body)
			}
			for _, hook := range []string{"http_connect", "http_connected", "request", "response"} {
				awaitHook(t, p, hook)
			}
			if len(leaf.CRLDistributionPoints) != 1 {
				t.Fatalf("CRL distribution points = %v", leaf.CRLDistributionPoints)
			}
			crlConn := dial(t, p.Addr)
			response, body = httpExchange(t, crlConn, "GET "+leaf.CRLDistributionPoints[0]+" HTTP/1.1\r\nHost: example.test\r\n\r\n")
			if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/pkix-crl" {
				t.Fatalf("CRL response = %d %v", response.StatusCode, response.Header)
			}
			crl, err := x509.ParseRevocationList(body)
			if err != nil {
				t.Fatal(err)
			}
			if err := crl.CheckSignatureFrom(p.CA); err != nil {
				t.Fatalf("CRL does not verify under proxy CA: %v", err)
			}
		})
	}
}

func TestCurlRegularProxy(t *testing.T) {
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skipf("curl integration requires the curl executable: %v", err)
	}
	tests := map[string]struct{ secure bool }{
		"success: HTTP":                        {},
		"success: HTTPS with trusted proxy CA": {secure: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var origin *proxytest.Origin
			scheme := "http"
			if tt.secure {
				origin, _ = startALPNOrigin(t)
				scheme = "https"
			} else {
				origin = proxytest.StartHTTPOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = io.WriteString(w, "secure origin")
				}))
			}
			p := proxytest.Start(t, proxytest.WithOrigin("example.test", origin))
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, curl, "--disable", "--silent", "--show-error", "--fail", "--noproxy", "", "--proxy", "http://"+p.Addr, "--cacert", filepath.Join(p.ConfDir, "mitmproxy-ca-cert.pem"), scheme+"://example.test/hello")
			if runtime.GOOS == "windows" {
				command.Args = append(command.Args, "--ssl-revoke-best-effort")
			}
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("curl: %v\n%s", err, output)
			}
			if diff := gocmp.Diff("secure origin", string(output)); diff != "" {
				t.Fatal(diff)
			}
			awaitHook(t, p, "request")
			awaitHook(t, p, "response")
		})
	}
}

func startALPNOrigin(t *testing.T) (*proxytest.Origin, <-chan []string) {
	t.Helper()
	key, ca, err := certs.CreateCA("proxytest", "HTTP origin CA", 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certs.DummyCert(key, ca, "example.test", []certs.GeneralName{
		certs.DNSName("example.test"), certs.DNSName("www.example.test"), certs.IPAddress(netip.MustParseAddr("127.0.0.1")),
	}, "", "http://example.test/origin.crl")
	if err != nil {
		t.Fatal(err)
	}
	offers := make(chan []string, 16)
	config := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.X509().Raw, ca.X509().Raw}, PrivateKey: key}},
		NextProtos:   []string{"h2", "http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			offers <- slices.Clone(hello.SupportedProtos)
			return nil, nil
		},
	}
	origin := proxytest.StartOrigin(t, func(raw net.Conn) {
		conn := tls.Server(raw, config)
		reader := bufio.NewReader(conn)
		for {
			request, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, request.Body)
			_ = request.Body.Close()
			if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nsecure origin"); err != nil {
				return
			}
		}
	})
	origin.CA, origin.Leaf = ca.X509(), leaf.X509()
	return origin, offers
}

func connectTunnel(t *testing.T, conn net.Conn, target string) {
	t.Helper()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	var head strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		head.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	if diff := gocmp.Diff("HTTP/1.1 200 Connection established\r\n\r\n", head.String()); diff != "" {
		t.Fatalf("CONNECT response (-want +got):\n%s", diff)
	}
	if reader.Buffered() != 0 {
		t.Fatal("CONNECT response unexpectedly included tunnel bytes")
	}
}

func httpExchange(t *testing.T, conn net.Conn, request string) (*http.Response, []byte) {
	t.Helper()
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, body
}
