// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// serverHooksAddon handles the server connection lifecycle hooks with
// optional callbacks, so tests mutate hook data the way addons do.
type serverHooksAddon struct {
	connect func(context.Context, *hookdata.ServerConnection) error
}

func (a *serverHooksAddon) ServerConnect(ctx context.Context, data *hookdata.ServerConnection) error {
	if a.connect == nil {
		return nil
	}
	return a.connect(ctx, data)
}

// poolDialer is a fake dialer: it counts calls, keeps the metadata
// snapshots it was given, optionally blocks until released, and consumes
// one queued error per call before producing a fresh pipe.
type poolDialer struct {
	t       *testing.T
	started chan struct{}
	mu      sync.Mutex
	calls   int
	seen    []*connection.Server
	peers   []net.Conn
	block   chan struct{}
	errs    []error
}

func (d *poolDialer) dial(ctx context.Context, srv *connection.Server) (layer.Conn, error) {
	d.mu.Lock()
	d.calls++
	d.seen = append(d.seen, srv)
	block := d.block
	var err error
	if len(d.errs) > 0 {
		err, d.errs = d.errs[0], d.errs[1:]
	}
	d.mu.Unlock()
	if d.started != nil {
		d.started <- struct{}{}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	a, b := net.Pipe()
	d.t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	d.mu.Lock()
	d.peers = append(d.peers, b)
	d.mu.Unlock()
	return memoryConn{Conn: a, input: a}, nil
}

// peer returns the remote end of the i-th dialed transport.
func (d *poolDialer) peer(i int) net.Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.peers[i]
}

func (d *poolDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func (d *poolDialer) snapshots() []*connection.Server {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.seen
}

func newPool(t *testing.T, dial layer.Dialer, addons ...any) (*serverPool, *connection.Client) {
	t.Helper()
	runner := newHookRunner(t, addons...)
	client := connection.NewClient(connection.Address{Host: "127.0.0.1", Port: 4}, connection.Address{Host: "127.0.0.1", Port: 8080}, 1)
	pool := newServerPool(t.Context(), client, dial, runner, runner.Manager.Do)
	t.Cleanup(func() {
		if err := pool.closeAll(context.WithoutCancel(t.Context())); err != nil {
			t.Errorf("closeAll: %v", err)
		}
	})
	return pool, client
}

// serverHooks filters the recorded hook names down to the server
// connection lifecycle, dropping manager events such as load.
func serverHooks(recorder *addontest.Recorder) []string {
	var names []string
	for _, name := range recorder.Hooks() {
		if strings.HasPrefix(name, "server_") {
			names = append(names, name)
		}
	}
	return names
}

func targetServer() *connection.Server {
	return connection.NewServer(&connection.Address{Host: "example.test", Port: 443})
}

type openResult struct {
	conn layer.Conn
	srv  *connection.Server
	err  error
}

func startOpen(t *testing.T, ctx context.Context, pool *serverPool, srv *connection.Server, opts layer.OpenOptions) <-chan openResult {
	t.Helper()
	done := make(chan openResult, 1)
	go func() {
		conn, actual, err := pool.Open(ctx, srv, opts)
		done <- openResult{conn, actual, err}
	}()
	return done
}

func TestPoolOpenLifecycle(t *testing.T) {
	tests := map[string]struct {
		kill      bool
		dialErr   error
		wantHooks []string
		wantErr   string
	}{
		"success": {
			wantHooks: []string{"server_connect", "server_connected"},
		},
		"killed": {
			kill:      true,
			wantHooks: []string{"server_connect", "server_connect_error"},
			wantErr:   "connection killed",
		},
		"dial failure": {
			dialErr:   errors.New("host unreachable"),
			wantHooks: []string{"server_connect", "server_connect_error"},
			wantErr:   "host unreachable",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			recorder := &addontest.Recorder{}
			killer := &serverHooksAddon{connect: func(_ context.Context, data *hookdata.ServerConnection) error {
				if tt.kill {
					reason := "killed by test"
					data.Server.Error = &reason
				}
				return nil
			}}
			dialer := &poolDialer{t: t}
			if tt.dialErr != nil {
				dialer.errs = []error{tt.dialErr}
			}
			pool, _ := newPool(t, dialer.dial, recorder, killer)
			srv := targetServer()
			got := await(t, startOpen(t, t.Context(), pool, srv, layer.OpenOptions{}))
			if diff := gocmp.Diff(tt.wantHooks, serverHooks(recorder)); diff != "" {
				t.Errorf("hooks (-want +got):\n%s", diff)
			}
			if tt.wantErr != "" {
				if got.err == nil || !strings.Contains(got.err.Error(), tt.wantErr) {
					t.Fatalf("Open error = %v, want %q", got.err, tt.wantErr)
				}
				if tt.kill && dialer.count() != 0 {
					t.Fatalf("killed connection dialed %d times", dialer.count())
				}
				if srv.Error == nil {
					t.Fatal("failure did not record srv.Error")
				}
				return
			}
			if got.err != nil {
				t.Fatal(got.err)
			}
			if got.conn == nil || got.srv != srv {
				t.Fatalf("Open = (%v, %v)", got.conn, got.srv)
			}
			if srv.State != connection.Open {
				t.Fatalf("state = %v, want open", srv.State)
			}
			if srv.TimestampStart == nil || srv.TimestampTCPSetup == nil || *srv.TimestampTCPSetup < *srv.TimestampStart {
				t.Fatalf("timestamps = %v, %v", srv.TimestampStart, srv.TimestampTCPSetup)
			}
			if srv.Peername == nil || srv.Sockname == nil {
				t.Fatalf("addresses = %v, %v", srv.Peername, srv.Sockname)
			}
		})
	}
}

func TestPoolRequiresAddress(t *testing.T) {
	dialer := &poolDialer{t: t}
	pool, _ := newPool(t, dialer.dial)
	_, _, err := pool.Open(t.Context(), connection.NewServer(nil), layer.OpenOptions{})
	if err == nil || !strings.Contains(err.Error(), "no hostname") {
		t.Fatalf("Open without address: %v", err)
	}
	if dialer.count() != 0 {
		t.Fatalf("dialed %d times", dialer.count())
	}
}

func TestPoolSingleFlight(t *testing.T) {
	dialer := &poolDialer{t: t, block: make(chan struct{})}
	pool, _ := newPool(t, dialer.dial)
	var setups atomic.Int32
	opts := layer.OpenOptions{Reuse: true, Setup: func(_ context.Context, conn layer.Conn, _ *connection.Server) (layer.Conn, error) {
		setups.Add(1)
		return conn, nil
	}}
	results := make([]<-chan openResult, 50)
	for i := range results {
		results[i] = startOpen(t, t.Context(), pool, targetServer(), opts)
	}
	close(dialer.block)
	first := await(t, results[0])
	if first.err != nil {
		t.Fatal(first.err)
	}
	for _, done := range results[1:] {
		got := await(t, done)
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.conn != first.conn || got.srv != first.srv {
			t.Fatalf("waiter got (%v, %v), want the established flight", got.conn, got.srv)
		}
	}
	if dialer.count() != 1 || setups.Load() != 1 {
		t.Fatalf("dials = %d, setups = %d, want 1, 1", dialer.count(), setups.Load())
	}
}

func TestPoolWinnerCancel(t *testing.T) {
	dialer := &poolDialer{t: t, block: make(chan struct{}), started: make(chan struct{}, 1)}
	pool, _ := newPool(t, dialer.dial)
	winnerCtx, cancel := context.WithCancel(t.Context())
	winner := startOpen(t, winnerCtx, pool, targetServer(), layer.OpenOptions{Reuse: true})
	await(t, dialer.started)
	waiter := startOpen(t, t.Context(), pool, targetServer(), layer.OpenOptions{Reuse: true})
	cancel()
	if got := await(t, winner); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("canceled winner = %+v", got)
	}
	// The flight runs under the handler's context, so the waiter still
	// receives the established connection.
	close(dialer.block)
	got := await(t, waiter)
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.conn == nil || dialer.count() != 1 {
		t.Fatalf("waiter after winner cancel: conn %v, %d dials", got.conn, dialer.count())
	}
}

func TestPoolFailureCache(t *testing.T) {
	dialErr := errors.New("connection refused")
	dialer := &poolDialer{t: t, errs: []error{dialErr}}
	pool, _ := newPool(t, dialer.dial)
	if _, _, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{Reuse: true}); err == nil {
		t.Fatal("first dial unexpectedly succeeded")
	}
	if _, _, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{Reuse: true}); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("cached failure = %v", err)
	}
	if dialer.count() != 1 {
		t.Fatalf("reuse retried the dial: %d calls", dialer.count())
	}
	conn, srv, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if conn == nil || srv.Error != nil || dialer.count() != 2 {
		t.Fatalf("fresh dial after failure: %v, %v, %d dials", conn, srv.Error, dialer.count())
	}
}

func TestPoolH2Redial(t *testing.T) {
	dialer := &poolDialer{t: t, block: make(chan struct{}), started: make(chan struct{}, 2)}
	alpns := []string{"http/1.1", "h2"}
	pool, client := newPool(t, dialer.dial)
	setup := func(ctx context.Context, conn layer.Conn, srv *connection.Server) (layer.Conn, error) {
		alpn := alpns[dialer.count()-1]
		err := pool.do(ctx, func(context.Context) error {
			srv.ALPN = []byte(alpn)
			return nil
		})
		return conn, err
	}
	client.ALPN = []byte("h2")
	opts := layer.OpenOptions{Reuse: true, Setup: setup}
	first := startOpen(t, t.Context(), pool, targetServer(), opts)
	await(t, dialer.started)
	requested := targetServer()
	waiter := startOpen(t, t.Context(), pool, requested, opts)
	close(dialer.block)
	a := await(t, first)
	b := await(t, waiter)
	if a.err != nil || b.err != nil {
		t.Fatal(a.err, b.err)
	}
	if string(a.srv.ALPN) != "http/1.1" || string(b.srv.ALPN) != "h2" {
		t.Fatalf("ALPN = %q, %q", a.srv.ALPN, b.srv.ALPN)
	}
	if b.conn == a.conn || b.srv.ID == a.srv.ID || b.srv.ID == requested.ID {
		t.Fatalf("h2 waiter joined a non-h2 connection: %v vs %v", b.srv, a.srv)
	}
	if dialer.count() != 2 {
		t.Fatalf("dials = %d, want 2", dialer.count())
	}
}

func TestPoolConnectAddrSnapshot(t *testing.T) {
	source := connection.Address{Host: "192.0.2.1", Port: 0}
	addon := &serverHooksAddon{connect: func(_ context.Context, data *hookdata.ServerConnection) error {
		data.Server.Sockname = &source
		return nil
	}}
	dialer := &poolDialer{t: t}
	pool, _ := newPool(t, dialer.dial, addon)
	srv := targetServer()
	if _, _, err := pool.Open(t.Context(), srv, layer.OpenOptions{}); err != nil {
		t.Fatal(err)
	}
	snapshots := dialer.snapshots()
	if len(snapshots) != 1 {
		t.Fatalf("dialed %d times", len(snapshots))
	}
	if snapshots[0] == srv {
		t.Fatal("dialer received the live metadata, not a snapshot")
	}
	if snapshots[0].Sockname == nil || snapshots[0].Sockname.Host != source.Host {
		t.Fatalf("dialer sockname = %v, want the connect_addr source", snapshots[0].Sockname)
	}
}

func TestPoolUpgradeOnce(t *testing.T) {
	dialer := &poolDialer{t: t}
	pool, _ := newPool(t, dialer.dial)
	srv := targetServer()
	raw, actual, err := pool.Open(t.Context(), srv, layer.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var setups atomic.Int32
	setup := func(_ context.Context, conn layer.Conn, upgraded *connection.Server) (layer.Conn, error) {
		setups.Add(1)
		return Record(conn), nil
	}
	type upgradeResult struct {
		conn layer.Conn
		err  error
	}
	results := make([]<-chan upgradeResult, 10)
	for i := range results {
		done := make(chan upgradeResult, 1)
		go func() {
			conn, _, err := pool.Upgrade(t.Context(), actual, setup)
			done <- upgradeResult{conn, err}
		}()
		results[i] = done
	}
	first := await(t, results[0])
	if first.err != nil {
		t.Fatal(first.err)
	}
	if first.conn == raw {
		t.Fatal("upgrade returned the raw transport")
	}
	for _, done := range results[1:] {
		got := await(t, done)
		if got.err != nil || got.conn != first.conn {
			t.Fatalf("concurrent upgrade = (%v, %v)", got.conn, got.err)
		}
	}
	if setups.Load() != 1 {
		t.Fatalf("setups = %d, want 1", setups.Load())
	}
	if conn, ok := pool.Lookup(actual); !ok || conn != first.conn {
		t.Fatalf("Lookup after upgrade = (%v, %t)", conn, ok)
	}
}

func TestPoolLookup(t *testing.T) {
	dialer := &poolDialer{t: t, block: make(chan struct{}), started: make(chan struct{}, 1)}
	pool, _ := newPool(t, dialer.dial)
	srv := targetServer()
	if _, ok := pool.Lookup(srv); ok {
		t.Fatal("Lookup found a connection before any Open")
	}
	done := startOpen(t, t.Context(), pool, srv, layer.OpenOptions{})
	await(t, dialer.started)
	if _, ok := pool.Lookup(srv); ok {
		t.Fatal("Lookup joined an in-flight establishment")
	}
	close(dialer.block)
	got := await(t, done)
	if got.err != nil {
		t.Fatal(got.err)
	}
	conn, ok := pool.Lookup(srv)
	if !ok || conn != got.conn {
		t.Fatalf("Lookup = (%v, %t), want the established transport", conn, ok)
	}
}

func TestPoolCloseAll(t *testing.T) {
	recorder := &addontest.Recorder{}
	dialer := &poolDialer{t: t}
	runner := newHookRunner(t, recorder)
	client := connection.NewClient(connection.Address{}, connection.Address{}, 1)
	pool := newServerPool(t.Context(), client, dialer.dial, runner, runner.Manager.Do)
	first := targetServer()
	second := connection.NewServer(&connection.Address{Host: "other.test", Port: 80})
	conns := make([]layer.Conn, 0, 2)
	for _, srv := range []*connection.Server{first, second} {
		conn, _, err := pool.Open(t.Context(), srv, layer.OpenOptions{})
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
	}
	if err := pool.closeAll(context.WithoutCancel(t.Context())); err != nil {
		t.Fatal(err)
	}
	var disconnected int
	for _, name := range serverHooks(recorder) {
		if name == "server_disconnected" {
			disconnected++
		}
	}
	if disconnected != 2 {
		t.Fatalf("server_disconnected fired %d times, want 2", disconnected)
	}
	for i, srv := range []*connection.Server{first, second} {
		if srv.State != connection.Closed || srv.TimestampEnd == nil {
			t.Fatalf("server %d after closeAll: state %v, end %v", i, srv.State, srv.TimestampEnd)
		}
		if _, err := conns[i].Read(make([]byte, 1)); err == nil {
			t.Fatalf("transport %d still readable after closeAll", i)
		}
	}
	if err := pool.closeAll(context.WithoutCancel(t.Context())); err != nil {
		t.Fatal(err)
	}
	if got := len(serverHooks(recorder)); got != 6 {
		t.Fatalf("repeated closeAll refired hooks: %d lifecycle calls", got)
	}
}

func TestPoolSetupFailure(t *testing.T) {
	recorder := &addontest.Recorder{}
	dialer := &poolDialer{t: t}
	pool, _ := newPool(t, dialer.dial, recorder)
	setupErr := errors.New("handshake refused")
	opts := layer.OpenOptions{Reuse: true, Setup: func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error) {
		return nil, setupErr
	}}
	srv := targetServer()
	if _, _, err := pool.Open(t.Context(), srv, opts); !errors.Is(err, setupErr) {
		t.Fatalf("Open with failing setup = %v", err)
	}
	want := []string{"server_connect", "server_connected", "server_disconnected"}
	if diff := gocmp.Diff(want, serverHooks(recorder)); diff != "" {
		t.Errorf("hooks (-want +got):\n%s", diff)
	}
	if _, err := dialer.peer(0).Read(make([]byte, 1)); err == nil {
		t.Fatal("transport still open after failed setup")
	}
	if _, _, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{Reuse: true}); !errors.Is(err, setupErr) {
		t.Fatalf("cached setup failure = %v", err)
	}
	if dialer.count() != 1 {
		t.Fatalf("reuse retried a failed setup: %d dials", dialer.count())
	}
}

func TestPoolOpenJoinsUpgrade(t *testing.T) {
	dialer := &poolDialer{t: t}
	pool, _ := newPool(t, dialer.dial)
	raw, actual, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{Reuse: true})
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	type upgradeResult struct {
		conn layer.Conn
		err  error
	}
	upgrading := make(chan upgradeResult, 1)
	go func() {
		conn, _, err := pool.Upgrade(t.Context(), actual, func(ctx context.Context, conn layer.Conn, _ *connection.Server) (layer.Conn, error) {
			close(entered)
			select {
			case <-release:
				return Record(conn), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
		upgrading <- upgradeResult{conn, err}
	}()
	await(t, entered)
	joined := startOpen(t, t.Context(), pool, targetServer(), layer.OpenOptions{Reuse: true})
	close(release)
	upgraded := await(t, upgrading)
	if upgraded.err != nil {
		t.Fatal(upgraded.err)
	}
	got := await(t, joined)
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.conn != upgraded.conn || got.conn == raw {
		t.Fatalf("joiner saw the raw transport during an upgrade: %v", got.conn)
	}
	if dialer.count() != 1 {
		t.Fatalf("dials = %d, want 1", dialer.count())
	}
}

func TestPoolSameServerTwice(t *testing.T) {
	dialer := &poolDialer{t: t}
	pool, _ := newPool(t, dialer.dial)
	srv := targetServer()
	first, firstSrv, err := pool.Open(t.Context(), srv, layer.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, secondSrv, err := pool.Open(t.Context(), srv, layer.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if second == first || secondSrv == firstSrv || secondSrv.ID == firstSrv.ID {
		t.Fatalf("one server described two connections: %v and %v", firstSrv, secondSrv)
	}
	if firstSrv != srv {
		t.Fatalf("first open renamed the caller's identity: %v", firstSrv)
	}
	if dialer.count() != 2 {
		t.Fatalf("dials = %d, want 2", dialer.count())
	}
	if secondSrv.State != connection.Open || secondSrv.Error != nil {
		t.Fatalf("fresh identity metadata: %v, %v", secondSrv.State, secondSrv.Error)
	}
}

func TestPoolTracksTransportClose(t *testing.T) {
	recorder := &addontest.Recorder{}
	dialer := &poolDialer{t: t}
	pool, _ := newPool(t, dialer.dial, recorder)
	conn, srv, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{Reuse: true})
	if err != nil {
		t.Fatal(err)
	}
	// The peer's half-close reaches the pool as EOF: the connection can no
	// longer satisfy a new request, so reuse dials again instead.
	if err := dialer.peer(0).Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("read after peer close: %v", err)
	}
	fresh, freshSrv, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{Reuse: true})
	if err != nil {
		t.Fatal(err)
	}
	if fresh == conn || freshSrv.ID == srv.ID || dialer.count() != 2 {
		t.Fatalf("dead transport was reused: %d dials", dialer.count())
	}
	// Identity lookup still serves the read side until the transport is
	// fully closed.
	if _, ok := pool.Lookup(srv); !ok {
		t.Fatal("Lookup dropped a half-closed transport")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := pool.Lookup(srv); ok {
		t.Fatal("Lookup returned a closed transport")
	}
}

func TestPoolCloseFiresDisconnectedOnce(t *testing.T) {
	recorder := &addontest.Recorder{}
	dialer := &poolDialer{t: t}
	pool, _ := newPool(t, dialer.dial, recorder)
	conn, srv, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{"server_connect", "server_connected", "server_disconnected"}
	if diff := gocmp.Diff(want, serverHooks(recorder)); diff != "" {
		t.Errorf("hooks (-want +got):\n%s", diff)
	}
	if srv.State != connection.Closed || srv.TimestampEnd == nil {
		t.Fatalf("metadata after close: %v, %v", srv.State, srv.TimestampEnd)
	}
}

func TestPoolHalfCloseWrite(t *testing.T) {
	dialer := &poolDialer{t: t}
	pool, _ := newPool(t, dialer.dial)
	conn, srv, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{Reuse: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var state connection.State
	if err := pool.do(t.Context(), func(context.Context) error {
		state = srv.State
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if state != connection.CanRead {
		t.Fatalf("state after CloseWrite = %v, want can-read", state)
	}
	// A half-closed connection is not reused.
	fresh, _, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{Reuse: true})
	if err != nil {
		t.Fatal(err)
	}
	if fresh == conn || dialer.count() != 2 {
		t.Fatalf("half-closed transport was reused: %d dials", dialer.count())
	}
}

func TestPoolReuseSkipsClosed(t *testing.T) {
	dialer := &poolDialer{t: t}
	runner := newHookRunner(t, &addontest.Recorder{})
	client := connection.NewClient(connection.Address{}, connection.Address{}, 1)
	pool := newServerPool(t.Context(), client, dialer.dial, runner, runner.Manager.Do)
	t.Cleanup(func() {
		if err := pool.closeAll(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	srv := targetServer()
	conn, _, err := pool.Open(t.Context(), srv, layer.OpenOptions{Reuse: true})
	if err != nil {
		t.Fatal(err)
	}
	reused, _, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{Reuse: true})
	if err != nil {
		t.Fatal(err)
	}
	if reused != conn || dialer.count() != 1 {
		t.Fatalf("matching open conn not reused: %d dials", dialer.count())
	}
	if err := runner.Manager.Do(t.Context(), func(context.Context) error {
		srv.State = connection.Closed
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fresh, freshSrv, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{Reuse: true})
	if err != nil {
		t.Fatal(err)
	}
	if fresh == conn || freshSrv.ID == srv.ID || dialer.count() != 2 {
		t.Fatalf("closed conn was reused: %d dials", dialer.count())
	}
	if !bytes.Equal(freshSrv.ALPN, nil) {
		t.Fatalf("fresh server inherited ALPN %q", freshSrv.ALPN)
	}
}
