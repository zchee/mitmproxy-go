// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/tcp"
)

// Behaviour of the fake layers, keyed by the handled client's ID so that
// concurrent connections of one test binary cannot observe each other.
var (
	topRuns   sync.Map // string -> func(context.Context, *layer.Context) error
	childRuns sync.Map // string -> func(context.Context, *layer.Context) error
)

const (
	topKind   hookdata.LayerKind = "test.handler-top"
	childKind hookdata.LayerKind = "test.handler-child"
)

type fakeLayer struct {
	kind hookdata.LayerKind
	runs *sync.Map
}

func (l *fakeLayer) Kind() hookdata.LayerKind { return l.kind }

func (l *fakeLayer) Run(ctx context.Context, c *layer.Context) error {
	v, ok := l.runs.Load(c.Data.Client.ID)
	if !ok {
		return errors.New("no behaviour registered for this client")
	}
	return v.(func(context.Context, *layer.Context) error)(ctx, c)
}

func init() {
	layer.Register(topKind, func(_ *layer.Context, spec hookdata.LayerSpec, _ layer.Layer) (layer.Layer, error) {
		return &fakeLayer{kind: spec.Kind, runs: &topRuns}, nil
	})
	layer.Register(childKind, func(_ *layer.Context, spec hookdata.LayerSpec, _ layer.Layer) (layer.Layer, error) {
		return &fakeLayer{kind: spec.Kind, runs: &childRuns}, nil
	})
}

// bindAddon publishes the test's layer behaviour under the connecting
// client's ID. It runs in client_connected, which the handler fires before
// it builds the top layer, so the fake layers always find their behaviour.
type bindAddon struct {
	t     *testing.T
	run   func(context.Context, *layer.Context) error
	child func(context.Context, *layer.Context) error
	ids   chan string
}

func (b *bindAddon) ClientConnected(_ context.Context, client *connection.Client) error {
	id := client.ID
	topRuns.Store(id, b.run)
	if b.child != nil {
		childRuns.Store(id, b.child)
	}
	b.t.Cleanup(func() { topRuns.Delete(id); childRuns.Delete(id) })
	b.ids <- id
	return nil
}

type handlerFixture struct {
	handler     *Handler
	connections *Connections
	recorder    *addontest.Recorder
	client      layer.Conn
	done        chan error
	ids         chan string
}

// id returns the connected client's ID without consuming it.
func (f *handlerFixture) id(t *testing.T) string {
	t.Helper()
	id := await(t, f.ids)
	f.ids <- id
	return id
}

// startHandler serves one layertest pipe through a new Handler, with run as
// the top layer's behaviour, and reports Handle's result on done.
func startHandler(t *testing.T, run func(context.Context, *layer.Context) error, addons ...any) *handlerFixture {
	t.Helper()
	f := &handlerFixture{
		recorder: &addontest.Recorder{},
		done:     make(chan error, 1),
		ids:      make(chan string, 1),
	}
	bind := &bindAddon{t: t, run: run, ids: f.ids}
	runner := newHookRunner(t, append([]any{f.recorder, bind}, addons...)...)
	f.connections = &Connections{}
	h, err := NewHandler(Config{
		Manager:     runner.Manager,
		Options:     runner.Manager.Options(),
		Connections: f.connections,
		Dialer:      (&poolDialer{t: t}).dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.handler = h
	clientConn, proxySide := layertest.Pipe(t)
	f.client = clientConn
	go func() {
		f.done <- h.Handle(t.Context(), proxySide, "regular", hookdata.LayerSpec{Kind: topKind})
	}()
	return f
}

func clientLifecycleHooks(recorder *addontest.Recorder) []string {
	var names []string
	for _, name := range recorder.Hooks() {
		if name == "client_connected" || name == "client_disconnected" {
			names = append(names, name)
		}
	}
	return names
}

func nextLayerCalls(recorder *addontest.Recorder) int {
	count := 0
	for _, name := range recorder.Hooks() {
		if name == "next_layer" {
			count++
		}
	}
	return count
}

func closedReadError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed)
}

func TestHandlerLifecycle(t *testing.T) {
	f := startHandler(t, func(_ context.Context, c *layer.Context) error {
		var buf [5]byte
		if _, err := io.ReadFull(c.Client, buf[:]); err != nil {
			return err
		}
		_, err := c.Client.Write(slices.Clone(buf[:]))
		return err
	})
	if _, err := f.client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	requireReplay(t, f.client, []byte("hello"))
	if err := await(t, f.done); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]string{"client_connected", "client_disconnected"}, clientLifecycleHooks(f.recorder)); diff != "" {
		t.Fatalf("lifecycle hooks (-want +got):\n%s", diff)
	}
	var disconnected *connection.Client
	for _, call := range f.recorder.Calls() {
		if call.Hook == "client_disconnected" {
			disconnected = call.Arg.(*connection.Client)
		}
	}
	if disconnected.State != connection.Closed || disconnected.TimestampEnd == nil {
		t.Fatalf("client after disconnect: state %v, end %v", disconnected.State, disconnected.TimestampEnd)
	}
	if disconnected.ProxyMode != "regular" {
		t.Fatalf("proxy mode = %q", disconnected.ProxyMode)
	}
	if n := f.connections.Len(); n != 0 {
		t.Fatalf("registry still holds %d connections", n)
	}
	// The layer returned, so the handler owns and closes the client socket.
	if _, err := f.client.Read(make([]byte, 1)); !closedReadError(err) {
		t.Fatalf("client socket after teardown: %v", err)
	}
}

type killAddon struct{}

func (killAddon) ClientConnected(_ context.Context, client *connection.Client) error {
	client.Error = new("local in-memory rejection")
	return nil
}

func TestHandlerKillAtConnect(t *testing.T) {
	ran := make(chan struct{}, 1)
	f := startHandler(t, func(context.Context, *layer.Context) error {
		ran <- struct{}{}
		return nil
	}, killAddon{})
	if err := await(t, f.done); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ran:
		t.Fatal("killed client still reached the top layer")
	default:
	}
	if diff := gocmp.Diff([]string{"client_connected", "client_disconnected"}, clientLifecycleHooks(f.recorder)); diff != "" {
		t.Fatalf("kill hooks (-want +got):\n%s", diff)
	}
	if _, err := f.client.Read(make([]byte, 1)); !closedReadError(err) {
		t.Fatalf("killed client socket: %v", err)
	}
}

func TestHandlerLayerFailureReported(t *testing.T) {
	failure := errors.New("layer gave up")
	f := startHandler(t, func(context.Context, *layer.Context) error { return failure })
	if err := await(t, f.done); !errors.Is(err, failure) {
		t.Fatalf("Handle = %v, want %v", err, failure)
	}
	if diff := gocmp.Diff([]string{"client_connected", "client_disconnected"}, clientLifecycleHooks(f.recorder)); diff != "" {
		t.Fatalf("failure hooks (-want +got):\n%s", diff)
	}
}

func TestHandlerInjectRouting(t *testing.T) {
	received := make(chan layer.Injected, 1)
	release := make(chan struct{})
	f := startHandler(t, func(ctx context.Context, c *layer.Context) error {
		select {
		case injected := <-c.Inject:
			received <- injected
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	id := f.id(t)
	live := flow.NewTCPFlow(&connection.Client{ID: id}, nil, true)
	message := &tcp.Message{FromClient: true, Content: []byte("injected")}
	if err := f.handler.Inject(t.Context(), layer.Injected{Flow: live, Message: message}); err != nil {
		t.Fatal(err)
	}
	injected := await(t, received)
	if injected.Flow != live || string(injected.Message.(*tcp.Message).Content) != "injected" {
		t.Fatalf("delivered injection = %+v", injected)
	}
	other := flow.NewTCPFlow(connection.NewClient(connection.Address{}, connection.Address{}, 1), nil, true)
	if err := f.handler.Inject(t.Context(), layer.Injected{Flow: other, Message: message}); !errors.Is(err, ErrFlowNotLive) {
		t.Fatalf("unknown connection: %v", err)
	}
	if err := f.handler.Inject(t.Context(), layer.Injected{Message: message}); !errors.Is(err, ErrFlowNotLive) {
		t.Fatalf("missing flow: %v", err)
	}
	close(release)
	if err := await(t, f.done); err != nil {
		t.Fatal(err)
	}
	if err := f.handler.Inject(t.Context(), layer.Injected{Flow: live, Message: message}); !errors.Is(err, ErrFlowNotLive) {
		t.Fatalf("finished connection: %v", err)
	}
}

type nextLayerDecider struct {
	stack hookdata.LayerStack
}

func (d *nextLayerDecider) NextLayer(_ context.Context, data *hookdata.NextLayer) error {
	data.Layer = slices.Clone(d.stack)
	return nil
}

type oneByteRecorder struct {
	layer.Recorder
	reading chan struct{}
	once    sync.Once
}

func (c *oneByteRecorder) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	return c.Recorder.Read(p[:min(len(p), 1)])
}

func TestHandlerFirstAskAfterBytes(t *testing.T) {
	replayed := make(chan []byte, 1)
	reading := make(chan struct{})
	f := startHandler(t, func(ctx context.Context, c *layer.Context) error {
		c.Client = &oneByteRecorder{Recorder: c.Client, reading: reading}
		child, err := layer.Next(ctx, c)
		if err != nil {
			return err
		}
		return child.Run(ctx, c)
	}, &nextLayerDecider{stack: hookdata.LayerStack{{Kind: childKind}}})
	id := f.id(t)
	childRuns.Store(id, func(_ context.Context, c *layer.Context) error {
		data, err := io.ReadAll(c.Client)
		replayed <- data
		return err
	})
	defer childRuns.Delete(id)

	// The selector reached its first read without an initial next_layer ask.
	await(t, reading)
	if got := nextLayerCalls(f.recorder); got != 0 {
		t.Fatalf("next_layer fired %d times before client bytes", got)
	}
	for _, b := range []byte("greet") {
		if _, err := f.client.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]byte("greet"), await(t, replayed)); diff != "" {
		t.Fatalf("replayed bytes (-want +got):\n%s", diff)
	}
	if err := await(t, f.done); err != nil {
		t.Fatal(err)
	}
	if got := nextLayerCalls(f.recorder); got == 0 {
		t.Fatal("next_layer never fired")
	}
}

func TestConnectionsSnapshotAndClose(t *testing.T) {
	f := startHandler(t, func(ctx context.Context, c *layer.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	id := f.id(t)
	if n := f.connections.Len(); n != 1 {
		t.Fatalf("Len() = %d, want 1", n)
	}
	snapshot, err := f.connections.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot) != 1 || snapshot[0].ID != id || snapshot[0].ProxyMode != "regular" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	// Close cancels every connection without waiting for its goroutines.
	f.connections.Close()
	if err := await(t, f.done); err != nil {
		t.Fatal(err)
	}
	if n := f.connections.Len(); n != 0 {
		t.Fatalf("Len() after Close = %d", n)
	}
	empty, err := f.connections.Snapshot(t.Context())
	if err != nil || len(empty) != 0 {
		t.Fatalf("snapshot after close = %v, %v", empty, err)
	}
}

func TestHandlerWatchdogExpiry(t *testing.T) {
	clock := &manualClock{current: time.Unix(100, 0)}
	entered := make(chan struct{})
	bind := &bindAddon{t: t, ids: make(chan string, 1), run: func(_ context.Context, c *layer.Context) error {
		close(entered)
		var buf [1]byte
		_, err := c.Client.Read(buf[:])
		return err
	}}
	runner := newHookRunner(t, bind)
	h, err := NewHandler(Config{
		Manager:     runner.Manager,
		Options:     runner.Manager.Options(),
		Connections: &Connections{},
		Dialer:      (&poolDialer{t: t}).dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.clock = clock
	clientConn, proxySide := layertest.Pipe(t)
	done := make(chan error, 1)
	go func() {
		done <- h.Handle(t.Context(), proxySide, "regular", hookdata.LayerSpec{Kind: topKind})
	}()
	await(t, entered)
	clock.advance(601 * time.Second)
	if err := await(t, done); err != nil {
		t.Fatalf("idle expiry must be an ordinary disconnect, got %v", err)
	}
	if _, err := clientConn.Read(make([]byte, 1)); !closedReadError(err) {
		t.Fatalf("expired client socket: %v", err)
	}
}

func TestHandlerRejectsHalfCloselessConn(t *testing.T) {
	entered := make(chan string, 1)
	bind := &bindAddon{t: t, ids: entered, run: func(_ context.Context, c *layer.Context) error {
		if err := c.Client.CloseWrite(); !errors.Is(err, ErrHalfCloseUnsupported) {
			return errors.Join(errors.New("CloseWrite must report missing support"), err)
		}
		return nil
	}}
	runner := newHookRunner(t, bind)
	h, err := NewHandler(Config{
		Manager:     runner.Manager,
		Options:     runner.Manager.Options(),
		Connections: &Connections{},
		Dialer:      (&poolDialer{t: t}).dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	ours, theirs := net.Pipe()
	t.Cleanup(func() { _ = ours.Close(); _ = theirs.Close() })
	done := make(chan error, 1)
	go func() {
		done <- h.Handle(t.Context(), theirs, "regular", hookdata.LayerSpec{Kind: topKind})
	}()
	await(t, entered)
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	// The conn stayed fully usable and was fully closed at teardown.
	if _, err := ours.Read(make([]byte, 1)); !closedReadError(err) {
		t.Fatalf("socket after teardown: %v", err)
	}
}

func TestNewHandlerValidation(t *testing.T) {
	runner := newHookRunner(t)
	valid := Config{
		Manager:     runner.Manager,
		Options:     runner.Manager.Options(),
		Connections: &Connections{},
		Dialer:      (&poolDialer{t: t}).dial,
	}
	tests := map[string]func(Config) Config{
		"manager":     func(c Config) Config { c.Manager = nil; return c },
		"options":     func(c Config) Config { c.Options = nil; return c },
		"connections": func(c Config) Config { c.Connections = nil; return c },
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewHandler(tt(valid)); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	if _, err := NewHandler(valid); err != nil {
		t.Fatal(err)
	}
	// The dialer has a default, so it may be left nil.
	noDialer := valid
	noDialer.Dialer = nil
	if _, err := NewHandler(noDialer); err != nil {
		t.Fatal(err)
	}
}

func TestHandlerServesConcurrentClients(t *testing.T) {
	ids := make(chan string, 8)
	run := func(ctx context.Context, c *layer.Context) error {
		child, err := layer.Next(ctx, c)
		if err != nil {
			return err
		}
		return child.Run(ctx, c)
	}
	bind := &bindAddon{t: t, ids: ids, run: run}
	runner := newHookRunner(t, bind, &nextLayerDecider{stack: hookdata.LayerStack{{Kind: childKind}}})
	connections := &Connections{}
	h, err := NewHandler(Config{
		Manager:     runner.Manager,
		Options:     runner.Manager.Options(),
		Connections: connections,
		Dialer:      (&poolDialer{t: t}).dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	echo := func(_ context.Context, c *layer.Context) error {
		data, err := io.ReadAll(c.Client)
		if err != nil {
			return err
		}
		_, err = c.Client.Write(data)
		return err
	}
	const clients = 5
	bind.child = echo
	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for i := range clients {
		clientConn, proxySide := layertest.Pipe(t)
		payload := []byte{byte('a' + i)}
		wg.Go(func() {
			errs <- h.Handle(t.Context(), proxySide, "regular", hookdata.LayerSpec{Kind: topKind})
		})
		wg.Go(func() {
			if _, err := clientConn.Write(payload); err != nil {
				t.Error(err)
				return
			}
			if err := clientConn.CloseWrite(); err != nil {
				t.Error(err)
				return
			}
			requireReplay(t, clientConn, payload)
		})
	}
	wg.Wait()
	for range clients {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if n := connections.Len(); n != 0 {
		t.Fatalf("registry holds %d connections after all handlers returned", n)
	}
}
