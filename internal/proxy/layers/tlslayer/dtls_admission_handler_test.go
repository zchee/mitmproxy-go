// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	dtls "github.com/pion/dtls/v3"

	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func TestDTLSReverseHandlerTupleReuse(t *testing.T) {
	tests := map[string]struct {
		plain bool
	}{
		"success: new ClientHello on a closed tuple":       {},
		"success: plain UDP still reaches the DTLS origin": {plain: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if t.Failed() {
					_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			key, ca, err := certs.CreateCA("DTLS reuse test", "DTLS origin CA", 2048)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := certs.DummyCert(key, ca, "example.test", []certs.GeneralName{certs.DNSName("example.test")}, "", "")
			if err != nil {
				t.Fatal(err)
			}
			origin, err := dtls.Listen("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &dtls.Config{ //nolint:staticcheck // Exercise the frozen hook configuration contract.
				Certificates:       []tls.Certificate{{Certificate: [][]byte{leaf.X509().Raw, ca.X509().Raw}, PrivateKey: key}},
				SupportedProtocols: []string{"custom"},
			})
			if err != nil {
				t.Fatal(err)
			}
			consumed := make(chan struct{})
			originDone := make(chan error, 2)
			originStopped := make(chan struct{})
			t.Cleanup(func() {
				cancel()
				_ = origin.Close()
				select {
				case <-originStopped:
				case <-time.After(30 * time.Second):
					t.Fatal("origin shutdown hung")
				}
			})
			go func() {
				defer close(originStopped)
				for range 2 {
					err := func() error {
						conn, err := origin.Accept()
						if err != nil {
							return err
						}
						defer func() { _ = conn.Close() }()
						stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
						defer stop()
						buf := make([]byte, 256)
						n, err := conn.Read(buf)
						if err == nil {
							_, err = conn.Write(buf[:n])
						}
						if err != nil {
							return err
						}
						select {
						case <-consumed:
							return nil
						case <-ctx.Done():
							return ctx.Err()
						}
					}()
					originDone <- err
					if err != nil {
						return
					}
				}
			}()
			observer := &dtlsAcceptanceObserver{ended: make(chan struct{}), disconnected: make(chan struct{}, 16)}
			p := proxytest.Start(t,
				proxytest.WithOptions(map[string]any{"mode": []string{"reverse:dtls://" + origin.Addr().String()}}),
				proxytest.WithTrustedCA(ca.X509()), proxytest.WithAddons(observer),
			)
			peer, err := net.ResolveUDPAddr("udp", p.Addr)
			if err != nil {
				t.Fatal(err)
			}
			local := "127.0.0.1:0"
			for round := range 2 {
				plain := round == 1 && tt.plain
				if err := p.Master.Do(ctx, func(context.Context) error {
					observer.plainClient = plain
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				socket, err := net.ListenPacket("udp4", local)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = socket.Close() })
				local = socket.LocalAddr().String()
				var conn net.Conn
				if !plain {
					session, err := dtls.Client(socket, peer, &dtls.Config{ //nolint:staticcheck // Real reused client tuple with the frozen configuration API.
						RootCAs: p.CAPool, ServerName: "example.test", SupportedProtocols: []string{"custom"},
					})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = session.Close() })
					if err := session.HandshakeContext(ctx); err != nil {
						t.Fatal(err)
					}
					conn = session
				}
				stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
				payload := fmt.Appendf(nil, "tuple round %d", round)
				buf := make([]byte, 256)
				var n int
				if plain {
					_, err = socket.WriteTo(payload, peer)
					if err == nil {
						n, _, err = socket.ReadFrom(buf)
					}
				} else {
					_, err = conn.Write(payload)
					if err == nil {
						n, err = conn.Read(buf)
					}
				}
				stop()
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(payload, buf[:n]); diff != "" {
					t.Fatal(diff)
				}
				if conn != nil {
					if err := conn.Close(); err != nil {
						t.Fatal(err)
					}
					select {
					case <-observer.disconnected:
					case <-ctx.Done():
						t.Fatal("tuple did not close:", ctx.Err())
					}
				}
				_ = socket.Close()
				select {
				case consumed <- struct{}{}:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				select {
				case err := <-originDone:
					if err != nil && !errors.Is(err, net.ErrClosed) {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if err := p.Master.Do(ctx, func(context.Context) error {
				if observer.originOpens != 2 {
					return fmt.Errorf("origin attempts = %d, want 2", observer.originOpens)
				}
				want := []string{"tls_clienthello", "tls_start_client", "tls_established_client", "tls_start_server", "tls_established_server"}
				if tt.plain {
					want = append(want, "tls_start_server", "tls_established_server")
				} else {
					want = append(want, want...)
				}
				if diff := cmp.Diff(want, observer.events); diff != "" {
					return fmt.Errorf("hook order (-want +got): %s", diff)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
