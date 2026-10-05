// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tcplayer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/options"
	"github.com/zchee/mitmproxy-go/tcp"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(layertest.Timeout):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("operation did not complete:\n%s", buf[:n])
		var zero T
		return zero
	}
}

type observer struct {
	events  []string
	flow    *flow.TCPFlow
	message func(context.Context, *flow.TCPFlow) error
	started chan *flow.TCPFlow
}

func (a *observer) TCPStart(_ context.Context, f *flow.TCPFlow) error {
	a.events = append(a.events, "tcp_start")
	a.flow = f
	if a.started != nil {
		a.started <- f
	}
	return nil
}

func (a *observer) TCPMessage(ctx context.Context, f *flow.TCPFlow) error {
	a.events = append(a.events, "tcp_message")
	if a.message != nil {
		return a.message(ctx, f)
	}
	return nil
}

func (a *observer) TCPEnd(_ context.Context, f *flow.TCPFlow) error {
	a.events = append(a.events, "tcp_end")
	if !f.Live {
		return errors.New("tcp_end must observe a live flow")
	}
	return nil
}

func (a *observer) TCPError(_ context.Context, _ *flow.TCPFlow) error {
	a.events = append(a.events, "tcp_error")
	return nil
}

type openPool struct {
	layer.ServerPool
	open func(context.Context, *connection.Server, layer.OpenOptions) (layer.Conn, *connection.Server, error)
}

func (p openPool) Open(ctx context.Context, server *connection.Server, opts layer.OpenOptions) (layer.Conn, *connection.Server, error) {
	return p.open(ctx, server, opts)
}

type session struct {
	client, server layer.Conn
	context        *layer.Context
	manager        *addon.Manager
	observed       *observer
	cancel         context.CancelFunc
	done           chan error
	finished       chan struct{}
	ignore         bool
}

func newSession(t *testing.T, observed *observer) *session {
	t.Helper()
	client, clientInput := layertest.Pipe(t)
	server, serverInput := layertest.Pipe(t)
	manager := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	if observed == nil {
		observed = &observer{}
	}
	if err := manager.Add(t.Context(), observed); err != nil {
		t.Fatal(err)
	}
	return &session{
		client: client, server: server, manager: manager, observed: observed,
		context: &layer.Context{
			Data: &hookdata.Context{
				Client: connection.NewClient(connection.Address{}, connection.Address{}, 1),
				Server: connection.NewServer(nil), Options: options.New(),
			},
			Client: proxy.Record(clientInput), Server: proxy.Record(serverInput), Record: proxy.Record,
			Hooks: &proxy.HookRunner{Manager: manager}, Do: manager.Do,
		},
	}
}

func (s *session) start(t *testing.T) {
	t.Helper()
	l, err := layer.Build(t.Context(), s.context, hookdata.LayerStack{{Kind: hookdata.LayerTCP, Ignore: s.ignore}})
	if err != nil {
		t.Fatal(err)
	}
	if l.Kind() != hookdata.LayerTCP {
		t.Fatalf("kind = %v", l.Kind())
	}
	ctx, cancel := context.WithCancel(t.Context())
	s.cancel = cancel
	s.done = make(chan error, 1)
	s.finished = make(chan struct{})
	t.Cleanup(func() {
		cancel()
		await(t, s.finished)
	})
	go func() {
		s.done <- l.Run(ctx, s.context)
		close(s.finished)
	}()
}

func (s *session) finish(t *testing.T) {
	t.Helper()
	for _, conn := range []layer.Conn{s.client, s.server} {
		if err := conn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	if err := await(t, s.done); err != nil {
		t.Fatal(err)
	}
	if s.observed.flow != nil && s.observed.flow.Live {
		t.Fatal("completed flow is still live")
	}
}

func exchange(t *testing.T, from, to layer.Conn, input, expected []byte) {
	t.Helper()
	if _, err := from.Write(input); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(expected))
	if _, err := io.ReadFull(to, got); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(expected, got); diff != "" {
		t.Fatal(diff)
	}
}

// Upstream test_open_connection and test_receive_data_before_server_connected.
func TestOpenConnection(t *testing.T) {
	tests := map[string]struct{ earlyData bool }{
		"open before data":              {},
		"receive data before connected": {earlyData: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, nil)
			server := s.context.Server
			s.context.Server = nil
			recorded := 0
			s.context.Record = func(conn layer.Conn) layer.Recorder {
				recorded++
				return proxy.Record(conn)
			}
			opening, release := make(chan struct{}), make(chan struct{})
			s.context.Pool = openPool{open: func(ctx context.Context, metadata *connection.Server, _ layer.OpenOptions) (layer.Conn, *connection.Server, error) {
				if diff := gocmp.Diff([]string{"tcp_start"}, s.observed.events); diff != "" {
					t.Error(diff)
				}
				close(opening)
				select {
				case <-release:
					return server, metadata, nil
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				}
			}}
			s.start(t)
			await(t, opening)
			if tt.earlyData {
				if _, err := s.client.Write([]byte("hello")); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			if tt.earlyData {
				got := make([]byte, 5)
				if _, err := io.ReadFull(s.server, got); err != nil || string(got) != "hello" {
					t.Fatalf("early data = %q, %v", got, err)
				}
			} else {
				exchange(t, s.client, s.server, []byte("hello"), []byte("hello"))
			}
			s.finish(t)
			if recorded != 1 || s.context.Server == nil || s.context.Server == server {
				t.Fatalf("opened transport was not wrapped and published: factory calls = %d, server = %v", recorded, s.context.Server)
			}
		})
	}
}

// Upstream test_open_connection_err: only tcp_error follows tcp_start.
func TestOpenConnectionError(t *testing.T) {
	s := newSession(t, nil)
	s.context.Server = nil
	want := errors.New("connection refused")
	s.context.Pool = openPool{open: func(context.Context, *connection.Server, layer.OpenOptions) (layer.Conn, *connection.Server, error) {
		return nil, nil, want
	}}
	s.start(t)
	if err := await(t, s.done); !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if diff := gocmp.Diff([]string{"tcp_start", "tcp_error"}, s.observed.events); diff != "" {
		t.Fatal(diff)
	}
	if s.observed.flow.Error.Msg != want.Error() {
		t.Fatalf("flow error = %v", s.observed.flow.Error)
	}
}

// Upstream test_simple: both directions are forwarded through message hooks.
func TestSimple(t *testing.T) {
	s := newSession(t, nil)
	s.start(t)
	exchange(t, s.client, s.server, []byte("hello!"), []byte("hello!"))
	exchange(t, s.server, s.client, []byte("hello back!"), []byte("hello back!"))
	s.finish(t)
	if diff := gocmp.Diff([]string{"tcp_start", "tcp_message", "tcp_message", "tcp_end"}, s.observed.events); diff != "" {
		t.Fatal(diff)
	}
	for i, m := range s.observed.flow.Messages {
		if m.FromClient != (i == 0) || m.Timestamp <= 0 {
			t.Fatalf("message %d = %+v", i, m)
		}
	}
}

// Upstream test_receive_data_after_half_close: the remaining direction stays open.
func TestReceiveDataAfterHalfClose(t *testing.T) {
	tests := map[string]struct{ clientFirst bool }{
		"client half-closes": {clientFirst: true},
		"server half-closes": {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, nil)
			s.start(t)
			first, second := s.client, s.server
			if !tt.clientFirst {
				first, second = second, first
			}
			if err := first.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if n, err := second.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("half-close read = %d, %v", n, err)
			}
			exchange(t, second, first, []byte("still open"), []byte("still open"))
			if err := second.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if err := await(t, s.done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRewriteMessage(t *testing.T) {
	s := newSession(t, &observer{message: func(_ context.Context, f *flow.TCPFlow) error {
		m := f.Messages[len(f.Messages)-1]
		m.Content = bytes.ToUpper(m.Content)
		// Direction is decided by the received event, not a handler's edit.
		m.FromClient = !m.FromClient
		return nil
	}})
	s.start(t)
	exchange(t, s.client, s.server, []byte("hello"), []byte("HELLO"))
	exchange(t, s.server, s.client, []byte("world"), []byte("WORLD"))
	s.finish(t)
}

type byteReader struct{ layer.Recorder }

func (r byteReader) Read(p []byte) (int, error) { return r.Recorder.Read(p[:min(1, len(p))]) }

func TestConcurrentDirections(t *testing.T) {
	var observed []*tcp.Message
	a := &observer{message: func(ctx context.Context, f *flow.TCPFlow) error {
		last := f.Messages[len(f.Messages)-1].Clone()
		count := len(f.Messages)
		_, err := addon.Concurrent(ctx, func(context.Context) error {
			runtime.Gosched()
			return nil
		})
		if err != nil {
			return err
		}
		if len(f.Messages) != count {
			t.Errorf("another reader appended while tcp_message was running: %d -> %d", count, len(f.Messages))
		}
		if diff := gocmp.Diff(last, f.Messages[len(f.Messages)-1]); diff != "" {
			t.Errorf("last message changed during handler: %s", diff)
		}
		observed = append(observed, last)
		return nil
	}}
	s := newSession(t, a)
	s.context.Client = byteReader{s.context.Client}
	s.context.Server = byteReader{s.context.Server}
	s.start(t)
	var senders sync.WaitGroup
	senders.Go(func() { exchange(t, s.client, s.server, bytes.Repeat([]byte("C"), 64), bytes.Repeat([]byte("C"), 64)) })
	senders.Go(func() { exchange(t, s.server, s.client, bytes.Repeat([]byte("S"), 64), bytes.Repeat([]byte("S"), 64)) })
	senders.Wait()
	s.finish(t)
	if len(observed) != 128 {
		t.Fatalf("message count = %d, want 128 one-byte reads", len(observed))
	}
	for _, m := range observed {
		want := []byte("S")
		if m.FromClient {
			want = []byte("C")
		}
		if diff := gocmp.Diff(want, m.Content); diff != "" {
			t.Fatal(diff)
		}
	}
}

func TestCancelUnblocksReaders(t *testing.T) {
	a := &observer{started: make(chan *flow.TCPFlow, 1)}
	s := newSession(t, a)
	s.start(t)
	await(t, a.started)
	s.cancel()
	if err := await(t, s.done); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel = %v", err)
	}
}

func TestConformance(t *testing.T) {
	layertest.Conformance(t, func(t *testing.T) layertest.Session {
		s := newSession(t, nil)
		return layertest.Session{
			Client: s.client, Server: s.server,
			ClientInput: s.context.Client, ServerInput: s.context.Server,
			ClientData: []byte("request\n"), ServerData: []byte("response\n"),
			Run: func(ctx context.Context) error {
				l, err := layer.Build(ctx, s.context, hookdata.LayerStack{{Kind: hookdata.LayerTCP}})
				if err != nil {
					return err
				}
				return l.Run(ctx, s.context)
			},
		}
	})
}
