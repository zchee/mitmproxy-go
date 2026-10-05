// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/master"
)

const upstreamPoolProbeKind hookdata.LayerKind = "test-upstream-pool"

type (
	upstreamPoolProbeKey struct{}
	upstreamPoolProbe    struct{}
)

func init() {
	layer.Register(upstreamPoolProbeKind, func(*layer.Context, hookdata.LayerSpec, layer.Layer) (layer.Layer, error) {
		return upstreamPoolProbe{}, nil
	})
}

func (upstreamPoolProbe) Kind() hookdata.LayerKind { return upstreamPoolProbeKind }

func (upstreamPoolProbe) Run(ctx context.Context, c *layer.Context) error {
	ctx.Value(upstreamPoolProbeKey{}).(chan *layer.Context) <- c
	<-ctx.Done()
	return ctx.Err()
}

type upstreamPoolObserver struct {
	connected    chan *connection.Server
	disconnected chan *connection.Server
}

func (*upstreamPoolObserver) Name() string { return "upstream-pool-observer" }

func (a *upstreamPoolObserver) ServerConnected(_ context.Context, data *hookdata.ServerConnection) error {
	a.connected <- data.Server.Clone()
	return nil
}

func (a *upstreamPoolObserver) ServerDisconnected(_ context.Context, data *hookdata.ServerConnection) error {
	a.disconnected <- data.Server.Clone()
	return nil
}

// newUpstreamPoolSession borrows the real handler's pool. Only its dial target
// is supplied by the test; setup, lifecycle hooks, ownership and joins are real.
func newUpstreamPoolSession(t *testing.T) (*upstreamPool, <-chan layer.Conn, *upstreamPoolObserver) {
	t.Helper()
	m := master.New(master.Config{})
	t.Cleanup(func() {
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	observer := &upstreamPoolObserver{connected: make(chan *connection.Server, 16), disconnected: make(chan *connection.Server, 16)}
	if err := m.Addons.Add(t.Context(), observer); err != nil {
		t.Fatal(err)
	}
	peers := make(chan layer.Conn, 16)
	handler, err := proxy.NewHandler(proxy.Config{
		Manager: m.Addons, Options: m.Options, Connections: new(proxy.Connections),
		Dialer: func(ctx context.Context, _ *connection.Server) (layer.Conn, error) {
			conn, peer := layertest.Pipe(t)
			select {
			case peers <- peer:
				return conn, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, _ := layertest.Pipe(t)
	contexts := make(chan *layer.Context, 1)
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), upstreamPoolProbeKey{}, contexts))
	done := make(chan error, 1)
	go func() {
		done <- handler.Handle(ctx, client, "regular", hookdata.LayerSpec{Kind: upstreamPoolProbeKind})
	}()
	c := await(t, contexts)
	pool := newUpstreamPool(ctx, c, c.Pool, false)
	t.Cleanup(func() {
		cancel()
		pool.stop()
		if err := await(t, done); err != nil {
			t.Error(err)
		}
	})
	return pool, peers, observer
}

func upstreamOrigin(host string) *connection.Server {
	srv := connection.NewServer(&connection.Address{Host: host, Port: 80})
	srv.TransportProtocol = connection.TCP
	srv.Via = &connection.ServerSpec{Scheme: "http", Address: connection.Address{Host: "proxy.test", Port: 3128}}
	return srv
}

func TestUpstreamPoolReuse(t *testing.T) {
	pool, peers, observer := newUpstreamPoolSession(t)
	first := upstreamOrigin("first.test")
	conn, actual, err := pool.Open(t.Context(), first, layer.OpenOptions{Reuse: true})
	if err != nil {
		t.Fatal(err)
	}
	peer := await(t, peers)
	physical := await(t, observer.connected)
	if diff := gocmp.Diff(first.Via.Address, *physical.Address); diff != "" {
		t.Fatalf("physical destination (-want +got):\n%s", diff)
	}
	if actual != first || actual.Peername == nil || actual.Sockname == nil || actual.TimestampTCPSetup == nil {
		t.Fatalf("logical connection metadata = %+v", actual)
	}
	if actual.ID == physical.ID || actual.Via == nil || actual.Address.Host != "first.test" {
		t.Fatalf("logical and physical metadata were conflated: origin=%+v proxy=%+v", actual, physical)
	}
	reused, metadata, err := pool.Open(t.Context(), upstreamOrigin("first.test"), layer.OpenOptions{Reuse: true})
	if err != nil || reused != conn || metadata != actual {
		t.Fatalf("reuse = %v, same transport=%v same metadata=%v", err, reused == conn, metadata == actual)
	}
	if found, ok := pool.Lookup(actual); !ok || found != conn {
		t.Fatalf("Lookup = %v, same transport=%v", ok, found == conn)
	}
	second, other, err := pool.Open(t.Context(), upstreamOrigin("second.test"), layer.OpenOptions{Reuse: true})
	if err != nil || second == conn || other == actual {
		t.Fatalf("distinct origin = %v, reused transport=%v metadata=%v", err, second == conn, other == actual)
	}
	_ = await(t, peers)
	_ = await(t, observer.connected)
	write(t, peer, "origin-data")
	expectRead(t, conn, "origin-data")
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	closed := await(t, observer.disconnected)
	if closed.ID != physical.ID || closed.State != connection.Closed {
		t.Fatalf("disconnected hook = %+v, want physical connection %s", closed, physical.ID)
	}
	if _, ok := pool.Lookup(first); ok {
		t.Fatal("closed physical transport still found through logical metadata")
	}
	reopened, fresh, err := pool.Open(t.Context(), first, layer.OpenOptions{Reuse: true})
	if err != nil || reopened == conn || fresh == first || fresh.ID == first.ID {
		t.Fatalf("reopen = %v, fresh metadata=%v", err, fresh)
	}
	if first.State != connection.Closed || first.TimestampEnd == nil {
		t.Fatalf("earlier flow metadata revived: %+v", first)
	}
}

func TestUpstreamPoolOpenSingleFlight(t *testing.T) {
	pool, peers, observer := newUpstreamPoolSession(t)
	srv := upstreamOrigin("origin.test")
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	setup := func(ctx context.Context, conn layer.Conn, _ *connection.Server) (layer.Conn, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
			if err := pool.c.Do(ctx, func(context.Context) error {
				srv.SNI = new("origin.test")
				return nil
			}); err != nil {
				return nil, err
			}
			return conn, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	canceled, cancel := context.WithCancel(t.Context())
	first := make(chan error, 1)
	go func() {
		_, _, err := pool.Open(canceled, srv, layer.OpenOptions{Reuse: true, Setup: setup})
		first <- err
	}()
	await(t, entered)
	if _, ok := pool.Lookup(srv); ok {
		t.Fatal("Lookup published a transport before setup completed")
	}
	cancel()
	if err := await(t, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter = %v", err)
	}
	type result struct {
		conn layer.Conn
		srv  *connection.Server
		err  error
	}
	results := make(chan result, 8)
	for range cap(results) {
		go func() {
			conn, actual, err := pool.Open(t.Context(), srv, layer.OpenOptions{Reuse: true, Setup: setup})
			results <- result{conn, actual, err}
		}()
	}
	close(release)
	var conn layer.Conn
	for range cap(results) {
		got := await(t, results)
		if got.err != nil || got.srv != srv || conn != nil && got.conn != conn {
			t.Fatalf("shared flight = %+v", got)
		}
		conn = got.conn
	}
	if calls.Load() != 1 || len(peers) != 1 || len(observer.connected) != 1 {
		t.Fatalf("setup=%d peers=%d connected=%d, want one of each", calls.Load(), len(peers), len(observer.connected))
	}
	write(t, await(t, peers), "still-open")
	expectRead(t, conn, "still-open")
}

func TestUpstreamPoolPlainUpgradeRefused(t *testing.T) {
	pool, _, _ := newUpstreamPoolSession(t)
	srv := upstreamOrigin("origin.test")
	if _, _, err := pool.Open(t.Context(), srv, layer.OpenOptions{}); err != nil {
		t.Fatal(err)
	}
	_, _, err := pool.Upgrade(t.Context(), srv, func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error) {
		t.Error("setup must not be silently skipped by the physical pool")
		return nil, io.ErrUnexpectedEOF
	})
	want := "httplayer: cannot upgrade an already-open plain upstream connection; supply setup when opening"
	if err == nil || err.Error() != want {
		t.Fatalf("Upgrade = %v, want %q", err, want)
	}
}
