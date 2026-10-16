// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/addons/proxyserver"
	"github.com/zchee/mitmproxy-go/addons/tlsconfig"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/modeserver"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/master"

	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/httplayer"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/tcplayer"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/tlslayer"
)

type transparentObservation struct {
	stage       string
	destination connection.Address
	sockname    connection.Address
	kinds       []hookdata.LayerKind
}

type transparentObserver struct {
	events chan transparentObservation
	done   chan struct{}
}

// ClientDisconnected records Handler completion before assertions inspect snapshots.
func (o *transparentObserver) ClientDisconnected(context.Context, *connection.Client) error {
	o.done <- struct{}{}
	return nil
}

// NextLayer snapshots the real selector's result after it has run.
func (o *transparentObserver) NextLayer(_ context.Context, data *hookdata.NextLayer) error {
	if len(data.Layer) == 0 {
		return nil
	}
	event := transparentObservation{stage: "selection"}
	if data.Context.Server.Address != nil {
		event.destination = *data.Context.Server.Address
	}
	if data.Context.Client.Sockname != nil {
		event.sockname = *data.Context.Client.Sockname
	}
	for _, spec := range data.Layer {
		event.kinds = append(event.kinds, spec.Kind)
	}
	o.events <- event
	return nil
}

func TestTransparentDestinationHandoff(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	tests := map[string]struct{ protocol string }{
		"HTTP": {protocol: "http"},
		"TLS":  {protocol: "tls"},
		"TCP":  {protocol: "tcp"},
	}
	for name, tt := range tests {
		for strategy := range map[string]struct{}{"eager": {}, "lazy": {}} {
			t.Run(name+"/"+strategy, func(t *testing.T) {
				m := master.New(master.Config{Logger: slog.New(slog.DiscardHandler)})
				t.Cleanup(func() {
					if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
						t.Error(err)
					}
				})
				configuration, err := proxyserver.New(proxy.Config{Manager: m.Addons, Options: m.Options, Connections: new(proxy.Connections), Logger: slog.New(slog.DiscardHandler)})
				if err != nil {
					t.Fatal(err)
				}
				if err := m.Addons.Add(t.Context(), configuration); err != nil {
					t.Fatal(err)
				}
				confdir := t.TempDir()
				values := map[string]any{"confdir": confdir, "rawtcp": true, "server": false, "connection_strategy": strategy}
				var originAddress string
				if tt.protocol == "tcp" {
					originAddress = transparentEchoOrigin(t)
				} else {
					origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path != "/captured" {
							t.Errorf("origin path = %q", r.URL.Path)
						}
						_, _ = io.WriteString(w, "captured destination")
					}))
					if tt.protocol == "tls" {
						origin.StartTLS()
						trust := filepath.Join(confdir, "origin-ca.pem")
						if err := os.WriteFile(trust, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0o600); err != nil {
							t.Fatal(err)
						}
						values["ssl_verify_upstream_trusted_ca"] = new(trust)
					} else {
						origin.Start()
					}
					t.Cleanup(origin.Close)
					originAddress = origin.Listener.Addr().String()
				}
				host, portText, err := net.SplitHostPort(originAddress)
				if err != nil {
					t.Fatal(err)
				}
				port, err := strconv.Atoi(portText)
				if err != nil {
					t.Fatal(err)
				}
				want := connection.Address{Host: host, Port: port}
				if err := m.Do(t.Context(), func(ctx context.Context) error { return m.Options.Update(ctx, values) }); err != nil {
					t.Fatal(err)
				}
				observer := &transparentObserver{events: make(chan transparentObservation, 32), done: make(chan struct{}, 1)}
				tlsAddon := tlsconfig.New(m.Options)
				if err := m.Addons.Add(t.Context(), nextlayer.New(m.Options), tlsAddon, observer); err != nil {
					t.Fatal(err)
				}
				if tt.protocol == "tls" {
					if err := m.Do(t.Context(), tlsAddon.Running); err != nil {
						t.Fatal(err)
					}
				}
				registry := new(proxy.Connections)
				t.Cleanup(registry.Close)
				realDial := proxy.NewDialer(net.Dialer{})
				handler, err := proxy.NewHandler(proxy.Config{Manager: m.Addons, Options: m.Options, Connections: registry, Logger: slog.Default(), Dialer: func(ctx context.Context, server *connection.Server) (layer.Conn, error) {
					event := transparentObservation{stage: "dial"}
					if server.Address != nil {
						event.destination = *server.Address
					}
					observer.events <- event
					return realDial(ctx, server)
				}})
				if err != nil {
					t.Fatal(err)
				}
				mode, err := modespec.Parse("transparent@127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				instance, err := modeserver.New(mode, modeserver.Config{Handler: handler, Logger: slog.New(slog.DiscardHandler)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = instance.Stop() })
				modeserver.SetTransparentLookupForTest(t, instance, func(ctx context.Context) error { return ctx.Err() }, func(ctx context.Context, raw *net.TCPConn) (connection.Address, error) {
					if err := m.Do(ctx, func(context.Context) error { return nil }); err != nil {
						return connection.Address{}, err
					}
					if _, ok := raw.LocalAddr().(*net.TCPAddr); !ok {
						t.Error("OS boundary did not receive a raw TCP socket")
					}
					return want, nil
				})
				if err := instance.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				listenerAddress := instance.ListenAddrs()[0]
				client, err := new(net.Dialer).DialContext(t.Context(), "tcp", listenerAddress.String())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if tt.protocol == "tls" {
					ca, err := os.ReadFile(filepath.Join(confdir, "mitmproxy-ca-cert.pem"))
					if err != nil {
						t.Fatal(err)
					}
					roots := x509.NewCertPool()
					if !roots.AppendCertsFromPEM(ca) {
						t.Fatal("proxy test CA was not loaded")
					}
					secure := tls.Client(client, &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12})
					if err := secure.HandshakeContext(t.Context()); err != nil {
						t.Fatal(err)
					}
					client = secure
				}
				if tt.protocol == "tcp" {
					payload := []byte("\x01captured-tcp")
					if _, err := client.Write(payload); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, len(payload))
					if _, err := io.ReadFull(client, got); err != nil {
						t.Fatal(err)
					}
					if diff := gocmp.Diff(payload, got); diff != "" {
						t.Fatal(diff)
					}
				} else {
					if _, err := io.WriteString(client, "GET /captured HTTP/1.1\r\nHost: "+originAddress+"\r\nConnection: close\r\n\r\n"); err != nil {
						t.Fatal(err)
					}
					response, err := http.ReadResponse(bufio.NewReader(client), nil)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if err != nil || response.StatusCode != http.StatusOK || string(body) != "captured destination" {
						t.Fatalf("origin response = %q, status=%d, error=%v", body, response.StatusCode, err)
					}
				}
				_ = client.Close()
				transparentAwait(t, observer.done)
				firstDial, firstSelection := -1, -1
				selected := make(map[hookdata.LayerKind]bool)
				for index := 0; len(observer.events) != 0; index++ {
					event := <-observer.events
					if diff := gocmp.Diff(want, event.destination); diff != "" {
						t.Fatalf("destination at %s (-want +got):\n%s", event.stage, diff)
					}
					if event.stage == "dial" && firstDial == -1 {
						firstDial = index
					}
					if event.stage == "selection" {
						if firstSelection == -1 {
							firstSelection = index
						}
						if diff := gocmp.Diff(listenerAddress, event.sockname); diff != "" {
							t.Fatalf("actual client sockname (-want +got):\n%s", diff)
						}
						for _, kind := range event.kinds {
							selected[kind] = true
						}
					}
				}
				if firstDial < 0 || firstSelection < 0 || (firstDial < firstSelection) != (strategy == "eager") {
					t.Fatalf("%s ordering: first dial=%d first selection=%d", strategy, firstDial, firstSelection)
				}
				wantKind := hookdata.LayerHTTP
				if tt.protocol == "tcp" {
					wantKind = hookdata.LayerTCP
				}
				if !selected[wantKind] || tt.protocol == "tls" && (!selected[hookdata.LayerClientTLS] || !selected[hookdata.LayerServerTLS]) {
					t.Fatalf("real protocol selections = %v, protocol=%s", selected, tt.protocol)
				}
			})
		}
	}
}

func transparentEchoOrigin(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		peer, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = peer.Close() }()
		_, _ = io.Copy(peer, peer)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		transparentAwait(t, done)
	})
	return listener.Addr().String()
}

func transparentAwait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("timed out joining transparent connection")
	}
}
