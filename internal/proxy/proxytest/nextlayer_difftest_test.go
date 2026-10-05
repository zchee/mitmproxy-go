// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package proxytest_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func TestDifferentialNextLayerCounts(t *testing.T) {
	difftest.UV(t)
	httpOrigin := proxytest.StartHTTPOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "origin reply")
	}))
	tlsHTTPOrigin := proxytest.StartTLSOrigin(t, []string{"127.0.0.1"}, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		for {
			request, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, request.Body)
			_ = request.Body.Close()
			if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\norigin reply"); err != nil {
				return
			}
		}
	})
	tlsOrigin := proxytest.StartTLSOrigin(t, []string{"127.0.0.1"}, nil)
	tcpOrigin := proxytest.StartOrigin(t, func(conn net.Conn) { _, _ = io.Copy(conn, conn) })
	tests := map[string]struct {
		mode        string
		origin      *proxytest.Origin
		secureProxy bool
		connect     bool
		tls         bool
		raw         bool
	}{
		"regular HTTP":                      {mode: "regular", origin: httpOrigin},
		"regular HTTPS through CONNECT":     {mode: "regular", origin: tlsHTTPOrigin, connect: true, tls: true},
		"secure web proxy TLS then CONNECT": {mode: "regular", origin: tlsHTTPOrigin, secureProxy: true, connect: true, tls: true},
		"reverse HTTPS":                     {mode: "reverse:https", origin: tlsHTTPOrigin, tls: true},
		"reverse TLS":                       {mode: "reverse:tls", origin: tlsOrigin, tls: true, raw: true},
		"reverse TCP":                       {mode: "reverse:tcp", origin: tcpOrigin, raw: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			counter := &nextLayerCounter{counts: make(map[*connection.Client]int), closed: make(chan int, 1)}
			mode := tt.mode
			if strings.HasPrefix(mode, "reverse:") {
				mode += "://" + tt.origin.Addr
			}
			p := proxytest.Start(t, proxytest.WithAddons(counter),
				proxytest.WithTrustedCA(tlsHTTPOrigin.CA), proxytest.WithTrustedCA(tlsOrigin.CA),
				proxytest.WithOptions(map[string]any{"mode": []string{mode}, "http2": false}))
			pythonAddr, pythonRoots, pythonCount := startCountingPython(t, tt.mode, tt.origin.Addr, tlsHTTPOrigin.CA, tlsOrigin.CA)

			// Both proxies receive exactly the same client script. Each write waits
			// for its reply before the next message, so read coalescing cannot hide
			// an invocation by combining separate application messages.
			script := func(addr string, roots *x509.CertPool) {
				conn := dial(t, addr)
				wrapTLS := func(serverName string) {
					client := tls.Client(conn, &tls.Config{
						RootCAs: roots, ServerName: serverName,
						MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
					})
					if err := client.HandshakeContext(t.Context()); err != nil {
						t.Fatal(err)
					}
					conn = client
				}
				if tt.secureProxy {
					wrapTLS("localhost")
				}
				if tt.connect {
					connectTunnel(t, conn, tt.origin.Addr)
				}
				if tt.tls {
					wrapTLS("127.0.0.1")
				}
				for i := range 2 {
					if tt.raw {
						exchange(t, conn, fmt.Sprintf("raw protocol message %d\n", i))
						continue
					}
					target := fmt.Sprintf("/message/%d", i)
					if tt.mode == "regular" && !tt.connect {
						target = "http://" + tt.origin.Addr + target
					}
					response, body := httpExchange(t, conn, "GET "+target+" HTTP/1.1\r\nHost: "+tt.origin.Addr+"\r\n\r\n")
					if response.StatusCode != http.StatusOK || string(body) != "origin reply" {
						t.Fatalf("scripted response = %d %q", response.StatusCode, body)
					}
				}
				if err := conn.Close(); err != nil {
					t.Fatal(err)
				}
			}
			script(pythonAddr, pythonRoots)
			want := pythonCount()
			script(p.Addr, p.CAPool)
			got := receive(t, counter.closed)
			t.Logf("next_layer per connection: Go=%d Python=%d", got, want)
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Errorf("next_layer count (-Python +Go):\n%s", diff)
			}
		})
	}
}

type nextLayerCounter struct {
	counts map[*connection.Client]int
	closed chan int
}

func (c *nextLayerCounter) NextLayer(_ context.Context, data *hookdata.NextLayer) error {
	c.counts[data.Context.Client]++
	return nil
}

func (c *nextLayerCounter) ClientDisconnected(_ context.Context, client *connection.Client) error {
	c.closed <- c.counts[client]
	delete(c.counts, client)
	return nil
}

func startCountingPython(t *testing.T, mode, origin string, authorities ...*x509.Certificate) (string, *x509.CertPool, func() int) {
	t.Helper()
	confdir := t.TempDir()
	var bundle []byte
	for _, ca := range authorities {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	}
	trusted := filepath.Join(confdir, "origin-ca.pem")
	if err := os.WriteFile(trusted, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cmd := exec.CommandContext(ctx, difftest.UV(t), "run", "--quiet", "--python", difftest.PythonVersion,
		"--script", "../../difftest/testdata/next_layer.py", mode, "0", origin, confdir, trusted)
	cmd.Env = append(cmd.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	lines := make(chan string, 8)
	done := make(chan struct{})
	var runErr error
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-ctx.Done():
			}
		}
		runErr = errors.Join(scanner.Err(), cmd.Wait())
		close(lines)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		receive(t, done)
		if t.Failed() {
			t.Logf("Python proxy: %v\n%s", runErr, stderr.String())
		}
	})
	readValue := func(prefix string) int {
		t.Helper()
		line := receive(t, lines)
		value, ok := strings.CutPrefix(line, prefix+" ")
		if !ok {
			t.Fatalf("Python proxy: expected %s, got %q", prefix, line)
		}
		n, err := strconv.Atoi(value)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	port := readValue("READY")
	ca, err := os.ReadFile(filepath.Join(confdir, "mitmproxy-ca-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("Python proxy CA is not valid PEM")
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), roots, func() int {
		count := readValue("COUNT")
		receive(t, done)
		if runErr != nil {
			t.Fatalf("Python proxy: %v\n%s", runErr, stderr.String())
		}
		return count
	}
}
