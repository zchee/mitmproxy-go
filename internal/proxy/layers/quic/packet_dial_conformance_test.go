// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettest"
	"github.com/zchee/mitmproxy-go/options"
)

var packetDialFixtures sync.Map

type packetDialFixtureLayer struct {
	run func(context.Context, *layer.Context) error
}

func (*packetDialFixtureLayer) Kind() hookdata.LayerKind { return "packet-dial-conformance-test" }
func (l *packetDialFixtureLayer) Run(ctx context.Context, c *layer.Context) error {
	return l.run(ctx, c)
}

func init() {
	layer.Register("packet-dial-conformance-test", func(c *layer.Context, _ hookdata.LayerSpec, _ layer.Layer) (layer.Layer, error) {
		value, ok := packetDialFixtures.Load(c.Data.Options)
		if !ok {
			return nil, errors.New("missing packet-dial conformance fixture")
		}
		return &packetDialFixtureLayer{run: value.(func(context.Context, *layer.Context) error)}, nil
	})
}

type packetDialHooks struct {
	reject       bool
	connected    []*connection.Server
	disconnected []*connection.Server
	failed       []*connection.Server
}

func (h *packetDialHooks) ServerConnect(_ context.Context, data *hookdata.ServerConnection) error {
	if h.reject {
		data.Server.Error = new("fixture rejected origin")
	}
	return nil
}

func (h *packetDialHooks) ServerConnected(_ context.Context, data *hookdata.ServerConnection) error {
	h.connected = append(h.connected, data.Server.Clone())
	return nil
}

func (h *packetDialHooks) ServerDisconnected(_ context.Context, data *hookdata.ServerConnection) error {
	h.disconnected = append(h.disconnected, data.Server.Clone())
	return nil
}

func (h *packetDialHooks) ServerConnectError(_ context.Context, data *hookdata.ServerConnection) error {
	h.failed = append(h.failed, data.Server.Clone())
	return nil
}

type ownedQueuedOrigin struct {
	layer.PacketTransport
	closes atomic.Int32
	reader sync.WaitGroup
	result chan error
}

func (p *ownedQueuedOrigin) Close() error {
	p.closes.Add(1)
	err := p.PacketTransport.Close()
	p.reader.Wait()
	return err
}

func packetDialConformance(t *testing.T) {
	t.Helper()
	tests := map[string]struct {
		cancelOpen bool
		rejected   bool
		earlyClose bool
	}{
		"success":       {},
		"cancellation":  {cancelOpen: true},
		"rejected-open": {rejected: true},
		"early-close":   {earlyClose: true},
	}
	entries := map[string]struct{ stream bool }{
		"Handle":        {stream: true},
		"HandlePackets": {},
	}
	for entry, transport := range entries {
		t.Run(entry, func(t *testing.T) {
			for name, test := range tests {
				t.Run(name, func(t *testing.T) {
					opts := options.New()
					manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
					t.Cleanup(manager.Close)
					recorder := new(addontest.Recorder)
					hooks := &packetDialHooks{reject: test.rejected}
					for _, observed := range []any{recorder, hooks} {
						if err := manager.Add(t.Context(), observed); err != nil {
							t.Fatal(err)
						}
					}
					registry := new(proxy.Connections)
					local := netip.MustParseAddrPort("127.0.0.1:21001")
					remote := netip.MustParseAddrPort("127.0.0.1:21002")
					var origin *ownedQueuedOrigin
					var peer *packettest.Transport
					var sharedServer *connection.Server
					var cancelOpen context.CancelFunc
					var acquired context.Context
					acquisitions := 0
					handler, err := proxy.NewHandler(proxy.Config{
						Manager: manager, Options: opts, Connections: registry,
						Logger: slog.New(slog.DiscardHandler),
						PacketDialer: func(ctx, lifetime context.Context, snapshot *connection.Server) (layer.PacketTransport, error) {
							acquisitions++
							acquired = ctx
							// Re-entering dispatch proves acquisition is not under its lock.
							if err := manager.Do(ctx, func(context.Context) error {
								if snapshot == sharedServer || snapshot.Address == sharedServer.Address || snapshot.Address.String() != remote.String() || snapshot.TimestampStart == nil {
									return errors.New("packet acquisition did not receive a private started snapshot")
								}
								snapshot.Address.Host = "private-snapshot.invalid"
								return nil
							}); err != nil {
								return nil, err
							}
							left, right, err := packettest.NewPair(lifetime, local, remote)
							if err != nil {
								return nil, err
							}
							peer = right
							origin = &ownedQueuedOrigin{PacketTransport: left, result: make(chan error, 1)}
							origin.reader.Go(func() {
								var data [1]byte
								_, _, err := left.ReadFrom(data[:])
								origin.result <- err
							})
							if test.cancelOpen {
								cancelOpen()
								<-ctx.Done()
							}
							return origin, nil
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					// Cleanup is a fallback only; ownership assertions below run first.
					defer func() {
						if origin != nil {
							_ = origin.PacketTransport.Close()
							origin.reader.Wait()
							_ = peer.Close()
						}
					}()
					run := func(ctx context.Context, c *layer.Context) error {
						if err := c.Do(ctx, func(context.Context) error {
							sharedServer = c.Data.Server
							sharedServer.Address = &connection.Address{Host: remote.Addr().String(), Port: int(remote.Port())}
							sharedServer.TransportProtocol = connection.UDP
							return nil
						}); err != nil {
							return err
						}
						openCtx, cancel := context.WithCancel(ctx)
						cancelOpen = cancel
						defer cancel()
						packets, actual, err := c.OpenPackets(openCtx, sharedServer)
						if err != nil {
							return err
						}
						cancel()
						if acquired.Err() == nil || origin.Context().Err() != nil {
							return errors.New("successful origin follows the acquisition context rather than Handler lifetime")
						}
						if actual != sharedServer || actual.Peername.String() != remote.String() || actual.Sockname.String() != local.String() || actual.Address.String() != remote.String() {
							return errors.New("queued origin endpoint metadata was not published")
						}
						if test.earlyClose {
							return origin.PacketTransport.Close()
						}
						if _, err := packets.WriteTo([]byte("queued request"), nil); err != nil {
							return err
						}
						var data [32]byte
						n, addr, err := peer.ReadFrom(data[:])
						if err != nil {
							return err
						}
						if string(data[:n]) != "queued request" || addr.String() != local.String() {
							return fmt.Errorf("queued origin received %q from %v", data[:n], addr)
						}
						return nil
					}
					packetDialFixtures.Store(opts, run)
					t.Cleanup(func() { packetDialFixtures.Delete(opts) })
					top := hookdata.LayerSpec{Kind: "packet-dial-conformance-test"}
					done := make(chan error, 1)
					if transport.stream {
						client, accepted := net.Pipe()
						t.Cleanup(func() { _ = client.Close(); _ = accepted.Close() })
						go func() { done <- handler.Handle(t.Context(), accepted, "regular", top) }()
					} else {
						client, accepted, err := packettest.NewPair(t.Context(), netip.MustParseAddrPort("127.0.0.1:22001"), netip.MustParseAddrPort("127.0.0.1:22002"))
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = client.Close(); _ = accepted.Close() })
						go func() { done <- handler.HandlePackets(t.Context(), accepted, "regular", top) }()
					}
					result := wireAwait(t, done)
					if (result != nil) != (test.cancelOpen || test.rejected) {
						t.Fatalf("Handler result=%v", result)
					}
					if registry.Len() != 0 {
						t.Fatal("Handler retained its live client")
					}
					var events []string
					for _, hook := range recorder.Hooks() {
						if strings.HasPrefix(hook, "server_") || strings.HasPrefix(hook, "client_") {
							events = append(events, hook)
						}
					}
					want := []string{"client_connected", "server_connect", "server_connected", "client_disconnected", "server_disconnected"}
					if test.cancelOpen || test.rejected {
						want = []string{"client_connected", "server_connect", "server_connect_error", "client_disconnected"}
					}
					if diff := gocmp.Diff(want, events); diff != "" {
						t.Fatalf("lifecycle hook order (-want +got):\n%s", diff)
					}
					if test.rejected {
						if acquisitions != 0 || origin != nil {
							t.Fatal("rejected origin reached packet acquisition")
						}
					} else {
						if acquisitions != 1 || origin == nil || origin.closes.Load() != 1 || origin.Context().Err() == nil {
							t.Fatal("Handler did not close its actual queued origin exactly once")
						}
						select {
						case err := <-origin.result:
							if !errors.Is(err, net.ErrClosed) {
								t.Fatalf("origin worker terminal cause=%v", err)
							}
						default:
							t.Fatal("origin reader outlived Handler return")
						}
					}
					if test.cancelOpen || test.rejected {
						if len(hooks.failed) != 1 || hooks.failed[0].Error == nil || hooks.failed[0].State != connection.Closed || len(hooks.disconnected) != 0 {
							t.Fatal("failed-open metadata/disconnect contract changed")
						}
					} else {
						if len(hooks.connected) != 1 || len(hooks.disconnected) != 1 {
							t.Fatal("queued origin connection lifecycle is not exactly once")
						}
						connected, disconnected := hooks.connected[0], hooks.disconnected[0]
						if connected.State != connection.Open || connected.TimestampTCPSetup == nil || disconnected.State != connection.Closed || disconnected.TimestampEnd == nil || connected.ID != disconnected.ID {
							t.Fatal("queued origin lifecycle metadata missing")
						}
					}
				})
			}
		})
	}
}
