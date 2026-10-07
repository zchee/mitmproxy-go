// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
	"github.com/zchee/mitmproxy-go/udp"

	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/udplayer"
)

type udpRelayAddon struct {
	start     func(context.Context, *flow.UDPFlow) error
	message   func(context.Context, *flow.UDPFlow) error
	connect   func(context.Context, *hookdata.ServerConnection) error
	end       func(context.Context, *flow.UDPFlow) error
	failed    func(context.Context, *flow.UDPFlow) error
	connected chan connection.Address
}

func (a *udpRelayAddon) UDPStart(ctx context.Context, f *flow.UDPFlow) error {
	if a.start != nil {
		return a.start(ctx, f)
	}
	return nil
}

func (a *udpRelayAddon) UDPMessage(ctx context.Context, f *flow.UDPFlow) error {
	if a.message != nil {
		return a.message(ctx, f)
	}
	return nil
}

func (a *udpRelayAddon) UDPEnd(ctx context.Context, f *flow.UDPFlow) error {
	if a.end != nil {
		return a.end(ctx, f)
	}
	return nil
}

func (a *udpRelayAddon) UDPError(ctx context.Context, f *flow.UDPFlow) error {
	if a.failed != nil {
		return a.failed(ctx, f)
	}
	return nil
}

func (a *udpRelayAddon) ServerConnect(ctx context.Context, d *hookdata.ServerConnection) error {
	if a.connect != nil {
		return a.connect(ctx, d)
	}
	return nil
}

func (a *udpRelayAddon) ServerConnected(_ context.Context, d *hookdata.ServerConnection) error {
	a.connected <- *d.Server.Sockname
	return nil
}

type udpRelayConfig struct {
	ignore, preopened, noFirst bool
	first                      []byte
	clock                      *manualClock
	addon                      *udpRelayAddon
	tuple                      *packettransport.TupleConn
	peer                       *net.UDPConn
	ctx                        context.Context
}

type udpRelayFixture struct {
	handler     *Handler
	connections *Connections
	manager     *addon.Manager
	recorder    *addontest.Recorder
	origin      net.PacketConn
	peer        *net.UDPConn
	tuple       *packettransport.TupleConn
	done        chan error
	flow        chan *flow.UDPFlow
	written     chan struct{}
	serverReady chan struct{}
	ctx         chan context.Context
	server      chan layer.PacketTransport
	addon       *udpRelayAddon
}

type observedUDPWrite struct {
	layer.PacketTransport
	written  chan struct{}
	reading  chan struct{}
	readOnce *sync.Once
}

func (c observedUDPWrite) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.reading != nil {
		c.readOnce.Do(func() { close(c.reading) })
	}
	return c.PacketTransport.ReadFrom(p)
}

func (c observedUDPWrite) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketTransport.WriteTo(p, addr)
	if err == nil {
		c.written <- struct{}{}
	}
	return n, err
}

func startUDPRelay(t *testing.T, config udpRelayConfig) *udpRelayFixture {
	t.Helper()
	origin, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	tuple, peer := config.tuple, config.peer
	if tuple == nil {
		tuple, peer = acceptedPackets(t, config.first)
	}
	if config.noFirst {
		if _, _, err := tuple.ReadFrom(nil); err != nil {
			t.Fatal(err)
		}
	}
	f := &udpRelayFixture{
		connections: new(Connections), recorder: new(addontest.Recorder), origin: origin,
		peer: peer, tuple: tuple, done: make(chan error, 1), flow: make(chan *flow.UDPFlow, 1),
		written: make(chan struct{}, 8), serverReady: make(chan struct{}), ctx: make(chan context.Context, 1), server: make(chan layer.PacketTransport, 1), addon: config.addon,
	}
	if f.addon == nil {
		f.addon = new(udpRelayAddon)
	}
	f.addon.connected = make(chan connection.Address, 1)
	start := f.addon.start
	f.addon.start = func(ctx context.Context, current *flow.UDPFlow) error {
		f.flow <- current
		if start != nil {
			return start(ctx, current)
		}
		return nil
	}
	bind := &bindAddon{t: t, ids: make(chan string, 1)}
	bind.run = func(ctx context.Context, c *layer.Context) error {
		f.ctx <- ctx
		if err := c.Do(ctx, func(context.Context) error { c.Data.Server.Address = addressOf(origin.LocalAddr()); return nil }); err != nil {
			return err
		}
		open := c.OpenPackets
		c.OpenPackets = func(ctx context.Context, server *connection.Server) (layer.PacketTransport, *connection.Server, error) {
			transport, actual, err := open(ctx, server)
			if err != nil {
				return nil, actual, err
			}
			f.server <- transport
			return observedUDPWrite{PacketTransport: transport, written: f.written, reading: f.serverReady, readOnce: new(sync.Once)}, actual, nil
		}
		if config.preopened {
			transport, actual, err := c.OpenPackets(ctx, c.Data.Server)
			if err != nil {
				return err
			}
			c.ServerPackets = c.RecordPackets(transport)
			if err := c.Do(ctx, func(context.Context) error { c.Data.Server = actual; return nil }); err != nil {
				return err
			}
		}
		selected, err := layer.Build(ctx, c, hookdata.LayerStack{{Kind: hookdata.LayerUDP, Ignore: config.ignore}})
		if err != nil {
			return err
		}
		return selected.Run(ctx, c)
	}
	runner := newHookRunner(t, f.recorder, bind, f.addon)
	f.manager = runner.Manager
	f.handler, err = NewHandler(Config{Manager: runner.Manager, Options: runner.Manager.Options(), Connections: f.connections})
	if err != nil {
		t.Fatal(err)
	}
	if config.clock != nil {
		f.handler.clock = config.clock
	}
	ctx := config.ctx
	if ctx == nil {
		ctx = t.Context()
	}
	go func() {
		defer close(f.done)
		f.done <- f.handler.HandlePackets(ctx, tuple, "reverse:udp://"+origin.LocalAddr().String(), hookdata.LayerSpec{Kind: topKind})
	}()
	t.Cleanup(func() {
		f.connections.Close()
		if err := await(t, f.done); err != nil {
			t.Errorf("UDP cleanup: %v", err)
		}
	})
	return f
}

func udpHooks(recorder *addontest.Recorder) []string {
	var hooks []string
	for _, name := range recorder.Hooks() {
		if strings.HasPrefix(name, "udp_") {
			hooks = append(hooks, name)
		}
	}
	return hooks
}

func requireDatagram(t *testing.T, input net.PacketConn, want []byte) net.Addr {
	t.Helper()
	window := make([]byte, layer.MaxUDPPacketBytes+1)
	n, addr, err := awaitPacketRead(t, input, window)
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(string(want), string(window[:n])); diff != "" {
		t.Fatalf("datagram (-want +got):\n%s", diff)
	}
	return addr
}

func TestUDPRelaySimpleUpstream(t *testing.T) {
	tests := map[string]struct {
		first, reply []byte
		mutate       bool
	}{
		"test_simple":     {first: []byte("hello!"), reply: []byte("hi")},
		"empty datagrams": {},
		"hook mutation":   {first: []byte("hello!"), reply: []byte("hi"), mutate: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			addon := &udpRelayAddon{message: func(_ context.Context, current *flow.UDPFlow) error {
				if test.mutate {
					current.Messages[len(current.Messages)-1].Content = append([]byte("changed-"), current.Messages[len(current.Messages)-1].Content...)
				}
				return nil
			}}
			f := startUDPRelay(t, udpRelayConfig{first: test.first, addon: addon})
			current := await(t, f.flow)
			first, reply := test.first, test.reply
			if test.mutate {
				first, reply = append([]byte("changed-"), first...), append([]byte("changed-"), reply...)
			}
			remote := requireDatagram(t, f.origin, first)
			if _, err := f.origin.WriteTo(test.reply, remote); err != nil {
				t.Fatal(err)
			}
			requireDatagram(t, f.peer, reply)
			if err := await(t, f.server).Close(); err != nil {
				t.Fatal(err)
			}
			if err := await(t, f.done); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff([]string{"udp_start", "udp_message", "udp_message", "udp_end"}, udpHooks(f.recorder)); diff != "" {
				t.Fatal(diff)
			}
			if err := f.manager.Do(t.Context(), func(context.Context) error {
				if current.Live || current.Error != nil || len(current.Messages) != 2 {
					t.Fatalf("terminal UDP state: live=%v error=%v messages=%d", current.Live, current.Error, len(current.Messages))
				}
				if !current.Messages[0].FromClient || current.Messages[1].FromClient {
					t.Error("wrong message directions")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if f.connections.Len() != 0 {
				t.Fatal("UDP connection was not evicted")
			}
		})
	}
}

func TestUDPRelayOpenConnectionUpstream(t *testing.T) {
	tests := map[string]struct{ ignore, preopened bool }{
		"test_open_connection":                   {ignore: true},
		"test_open_connection already connected": {ignore: true, preopened: true},
		"test_ignore true":                       {ignore: true},
		"test_ignore false":                      {},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f := startUDPRelay(t, udpRelayConfig{first: []byte("hello!"), ignore: test.ignore, preopened: test.preopened})
			remote := requireDatagram(t, f.origin, []byte("hello!"))
			if _, err := f.origin.WriteTo([]byte("reply"), remote); err != nil {
				t.Fatal(err)
			}
			requireDatagram(t, f.peer, []byte("reply"))
			if err := await(t, f.server).Close(); err != nil {
				t.Fatal(err)
			}
			if err := await(t, f.done); err != nil {
				t.Fatal(err)
			}
			var want []string
			if !test.ignore {
				want = []string{"udp_start", "udp_message", "udp_message", "udp_end"}
			}
			if diff := gocmp.Diff(want, udpHooks(f.recorder)); diff != "" {
				t.Fatal(diff)
			}
			count := 0
			for _, hook := range f.recorder.Hooks() {
				if hook == "server_connect" {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("server opened %d times, want 1", count)
			}
		})
	}
}

func TestUDPRelayServerFirst(t *testing.T) {
	f := startUDPRelay(t, udpRelayConfig{noFirst: true})
	local := await(t, f.addon.connected)
	await(t, f.serverReady)
	if _, err := f.origin.WriteTo([]byte("greeting"), &net.UDPAddr{IP: net.ParseIP(local.Host), Port: local.Port}); err != nil {
		t.Fatal(err)
	}
	requireDatagram(t, f.peer, []byte("greeting"))
}

func TestUDPRelayOpenErrorUpstream(t *testing.T) {
	f := startUDPRelay(t, udpRelayConfig{addon: &udpRelayAddon{connect: func(_ context.Context, d *hookdata.ServerConnection) error {
		d.Server.Error = new("Connect call failed")
		return nil
	}}})
	current := await(t, f.flow)
	if err := await(t, f.done); err == nil || !strings.Contains(err.Error(), "Connect call failed") {
		t.Fatalf("dial failure = %v", err)
	}
	if diff := gocmp.Diff([]string{"udp_start", "udp_error"}, udpHooks(f.recorder)); diff != "" {
		t.Fatal(diff)
	}
	if err := f.manager.Do(t.Context(), func(context.Context) error {
		if current.Live || current.Error == nil || !strings.Contains(current.Error.Msg, "Connect call failed") {
			t.Errorf("failed UDP state: live=%v error=%v", current.Live, current.Error)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestUDPRelayPendingOpenUpstream(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := startUDPRelay(t, udpRelayConfig{first: []byte("hello!"), addon: &udpRelayAddon{connect: func(ctx context.Context, _ *hookdata.ServerConnection) error {
		close(entered)
		_, err := addon.Concurrent(ctx, func(ctx context.Context) error {
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		return err
	}}})
	await(t, entered)
	if _, err := f.peer.Write([]byte("during dial")); err != nil {
		t.Fatal(err)
	}
	close(release)
	requireDatagram(t, f.origin, []byte("hello!"))
	requireDatagram(t, f.origin, []byte("during dial"))
}

func TestUDPRelayInjectionUpstream(t *testing.T) {
	ready := make(chan struct{})
	var f *udpRelayFixture
	f = startUDPRelay(t, udpRelayConfig{noFirst: true, addon: &udpRelayAddon{start: func(ctx context.Context, current *flow.UDPFlow) error {
		ctx, err := addon.Concurrent(ctx, func(ctx context.Context) error {
			select {
			case <-ready:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		if err != nil {
			return err
		}
		message := udp.NewMessage(true, []byte("hello!"))
		if err := f.handler.Inject(ctx, layer.Injected{Flow: current, Message: message}); err != nil {
			return err
		}
		message.Content[0], message.FromClient = 'X', false
		return nil
	}}})
	close(ready)
	current := await(t, f.flow)
	requireDatagram(t, f.origin, []byte("hello!"))
	message := udp.NewMessage(false, []byte("I have already done the greeting for you."))
	if err := f.handler.Inject(t.Context(), layer.Injected{Flow: current, Message: message}); err != nil {
		t.Fatal(err)
	}
	message.Content[0], message.FromClient = 'X', true
	requireDatagram(t, f.peer, []byte("I have already done the greeting for you."))
	f.connections.Close()
	if err := await(t, f.done); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Do(t.Context(), func(context.Context) error {
		var messages []string
		for _, message := range current.Messages {
			messages = append(messages, string(message.Content))
		}
		if diff := gocmp.Diff([]string{"hello!", "I have already done the greeting for you."}, messages); diff != "" {
			t.Error(diff)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.handler.Inject(t.Context(), layer.Injected{Flow: current, Message: udp.NewMessage(true, nil)}); !errors.Is(err, ErrFlowNotLive) {
		t.Fatalf("closed UDP injection = %v", err)
	}
}

func TestUDPRelayIdleExpiry(t *testing.T) {
	tests := map[string]struct{ reset bool }{"twenty second boundary": {}, "another datagram resets expiry": {reset: true}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			clock := new(manualClock)
			f := startUDPRelay(t, udpRelayConfig{first: []byte("first"), clock: clock})
			ctx := await(t, f.ctx)
			requireDatagram(t, f.origin, []byte("first"))
			await(t, f.written)
			clock.advance(19 * time.Second)
			if ctx.Err() != nil {
				t.Fatal("expired before twenty seconds")
			}
			if test.reset {
				if _, err := f.peer.Write([]byte("reset")); err != nil {
					t.Fatal(err)
				}
				requireDatagram(t, f.origin, []byte("reset"))
				await(t, f.written)
				clock.advance(19 * time.Second)
			}
			clock.advance(time.Second - time.Nanosecond)
			if ctx.Err() != nil {
				t.Fatal("expired before boundary")
			}
			clock.advance(time.Nanosecond)
			if ctx.Err() == nil {
				t.Fatal("did not expire at boundary")
			}
			if err := await(t, f.done); err != nil {
				t.Fatal(err)
			}
			if f.connections.Len() != 0 || f.tuple.Context().Err() == nil {
				t.Fatal("expired tuple was not evicted")
			}
			if got := udpHooks(f.recorder); !slices.Contains(got, "udp_end") || slices.Contains(got, "udp_error") {
				t.Fatalf("idle cancellation must emit udp_end only: %v", got)
			}
		})
	}
}

func TestUDPRelayLargeDatagram(t *testing.T) {
	f := startUDPRelay(t, udpRelayConfig{first: []byte("small")})
	requireDatagram(t, f.origin, []byte("small"))
	if err := packettransport.ConfigureSocketBuffers(f.peer); err != nil {
		t.Fatal(err)
	}
	if err := packettransport.ConfigureSocketBuffers(f.origin.(*net.UDPConn)); err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("x"), layer.MaxUDPPacketBytes)
	if _, err := f.peer.Write(content); err != nil {
		t.Fatal(err)
	}
	remote := requireDatagram(t, f.origin, content)
	if _, err := f.origin.WriteTo(content, remote); err != nil {
		t.Fatal(err)
	}
	requireDatagram(t, f.peer, content)
}

func TestUDPRelayInterceptionCancellation(t *testing.T) {
	tests := map[string]struct{ atStart bool }{"intercepted message": {}, "intercepted start": {atStart: true}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			entered := make(chan struct{})
			intercept := func(_ context.Context, current *flow.UDPFlow) error { current.Intercept(); close(entered); return nil }
			addon := new(udpRelayAddon)
			if test.atStart {
				addon.start = intercept
			} else {
				addon.message = intercept
			}
			f := startUDPRelay(t, udpRelayConfig{first: []byte("intercepted"), addon: addon})
			current := await(t, f.flow)
			await(t, entered)
			f.connections.Close()
			if err := await(t, f.done); err != nil {
				t.Fatal(err)
			}
			if err := f.manager.Do(t.Context(), func(context.Context) error {
				if current.Live {
					t.Error("canceled UDP flow is still live")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(udpHooks(f.recorder), "udp_end") || f.connections.Len() != 0 {
				t.Fatal("shutdown did not emit udp_end and evict the tuple")
			}
		})
	}
}

func TestUDPRelaySharedListenerExpiryAndReuse(t *testing.T) {
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	observed := observePacketReads(t, socket)
	listener := packettransport.NewListener(t.Context(), observed)
	t.Cleanup(func() { _ = listener.Close() })
	await(t, observed.ready)
	accept := func(peer *net.UDPConn, content string) *packettransport.TupleConn {
		if _, err := peer.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		if err := await(t, observed.received); err != nil {
			t.Fatalf("shared listener datagram socket delivery: %v", err)
		}
		return awaitTupleAdmission(t, listener)
	}
	peer := func() *net.UDPConn {
		p, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	clock := new(manualClock)
	peer1, peer2 := peer(), peer()
	first := startUDPRelay(t, udpRelayConfig{tuple: accept(peer1, "one"), peer: peer1, clock: clock})
	second := startUDPRelay(t, udpRelayConfig{tuple: accept(peer2, "two"), peer: peer2, clock: clock})
	requireDatagram(t, first.origin, []byte("one"))
	await(t, first.written)
	requireDatagram(t, second.origin, []byte("two"))
	await(t, second.written)
	ctx2 := await(t, second.ctx)
	clock.advance(19 * time.Second)
	if _, err := peer2.Write([]byte("renewed")); err != nil {
		t.Fatal(err)
	}
	if err := await(t, observed.received); err != nil {
		t.Fatalf("renewed datagram socket delivery: %v", err)
	}
	requireDatagram(t, second.origin, []byte("renewed"))
	await(t, second.written)
	clock.advance(time.Second)
	if err := await(t, first.done); err != nil {
		t.Fatal(err)
	}
	if first.tuple.Context().Err() == nil || ctx2.Err() != nil {
		t.Fatal("expiring one tuple affected its neighbour")
	}
	if _, err := peer2.Write([]byte("still live")); err != nil {
		t.Fatal(err)
	}
	if err := await(t, observed.received); err != nil {
		t.Fatalf("live neighbour datagram socket delivery: %v", err)
	}
	requireDatagram(t, second.origin, []byte("still live"))
	reused := startUDPRelay(t, udpRelayConfig{tuple: accept(peer1, "reused"), peer: peer1, clock: clock})
	requireDatagram(t, reused.origin, []byte("reused"))
	if reused.tuple == first.tuple || reused.tuple.Context().Err() != nil {
		t.Fatal("tuple reuse did not create a new transport")
	}
	var oldID, newID string
	oldFlow, newFlow := await(t, first.flow), await(t, reused.flow)
	if err := first.manager.Do(t.Context(), func(context.Context) error { oldID = oldFlow.ID; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := reused.manager.Do(t.Context(), func(context.Context) error { newID = newFlow.ID; return nil }); err != nil {
		t.Fatal(err)
	}
	if oldID == newID {
		t.Fatal("tuple reuse migrated the old flow")
	}
}
