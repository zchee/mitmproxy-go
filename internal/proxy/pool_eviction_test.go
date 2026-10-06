// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

type poolEndBarrier struct {
	entered chan struct{}
	release chan struct{}
}

func (*poolEndBarrier) Name() string { return "pool_end_barrier" }

func (a *poolEndBarrier) ServerDisconnected(context.Context, *hookdata.ServerConnection) error {
	close(a.entered)
	<-a.release
	return nil
}

func TestPoolCompletedRetirementEviction(t *testing.T) {
	tests := map[string]struct{ rotations int }{
		"success: repeated same-origin rotations": {rotations: 16},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			dialer := &poolDialer{t: t}
			pool, _ := newPool(t, dialer.dial)
			target := targetServer()
			for rotation := range test.rotations {
				conn, srv, err := pool.Open(t.Context(), target, layer.OpenOptions{Reuse: true})
				if err != nil {
					t.Fatal(err)
				}
				if rotation > 0 && (srv == target || srv.ID == target.ID) {
					t.Fatal("completed metadata was reused for a fresh transport")
				}
				target = srv
				pool.Retire(srv)
				pool.mu.Lock()
				retained := len(pool.entries)
				pool.mu.Unlock()
				if retained != 1 {
					t.Fatalf("rotation %d: accepted draining lease membership = %d, want 1", rotation, retained)
				}
				if err := conn.Close(); err != nil {
					t.Fatal(err)
				}
				pool.mu.Lock()
				retained = len(pool.entries)
				pool.mu.Unlock()
				if retained != 0 {
					t.Fatalf("rotation %d: completed pool membership = %d, want 0", rotation, retained)
				}
			}
			if got := dialer.count(); got != test.rotations {
				t.Fatalf("dials = %d, want %d", got, test.rotations)
			}
		})
	}
}

func TestPoolGracefulOriginRotationEviction(t *testing.T) {
	tests := map[string]struct{ rotations int }{
		"success: completed wire GOAWAY rotations": {rotations: 16},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var peerConn layer.Conn
			pool, _ := newPool(t, func(context.Context, *connection.Server) (layer.Conn, error) {
				conn, peer := layertest.Pipe(t)
				peerConn = peer
				return conn, nil
			})
			for rotation := range test.rotations {
				conn, srv, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{Reuse: true})
				if err != nil {
					t.Fatal(err)
				}
				peer := peerConn
				clientEngine, err := h2.New(conn, h2.Config{Client: true, Descriptor: layer.EndpointDescriptor{Identity: "client"}, ValidateInboundHeaders: true})
				if err != nil {
					t.Fatal(err)
				}
				serverEngine := http2.NewFramer(peer, peer)
				written := make(chan uint32, 1)
				ctx, cancel := context.WithCancel(t.Context())
				clientDone, serverDone := make(chan struct{}), make(chan struct{})
				t.Cleanup(func() { cancel(); await(t, clientDone); await(t, serverDone) })
				go func() {
					_ = clientEngine.Run(ctx)
					_ = conn.Close()
					close(clientDone)
				}()
				go func() {
					defer close(serverDone)
					defer func() { _ = peer.Close() }()
					stop := context.AfterFunc(ctx, func() { _ = peer.Close() })
					defer stop()
					preface := make([]byte, len(http2.ClientPreface))
					if _, err := io.ReadFull(peer, preface); err != nil || string(preface) != http2.ClientPreface {
						t.Errorf("origin preface = %q, %v", preface, err)
						return
					}
					if err := serverEngine.WriteSettings(); err != nil {
						t.Error(err)
						return
					}
					for {
						frame, err := serverEngine.ReadFrame()
						if err != nil {
							t.Error(err)
							return
						}
						switch frame := frame.(type) {
						case *http2.SettingsFrame:
							if !frame.IsAck() {
								if err := serverEngine.WriteSettingsAck(); err != nil {
									t.Error(err)
									return
								}
							}
						case *http2.HeadersFrame:
							written <- frame.StreamID
							_, _ = io.Copy(io.Discard, peer)
							return
						}
					}
				}()
				identity, err := clientEngine.OpenStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := clientEngine.Send(ctx, h2.Event{Kind: h2.Headers, Identity: identity, Headers: []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "origin.test"}, {Name: ":path", Value: "/"}}, EndStream: true}); err != nil {
					t.Fatal(err)
				}
				streamID := await(t, written)
				if err := serverEngine.WriteGoAway(streamID, http2.ErrCodeNo, nil); err != nil {
					t.Fatal(err)
				}
				goaway, err := clientEngine.Receive(ctx)
				if err != nil || goaway.Kind != h2.GoAway {
					t.Fatalf("GOAWAY = %+v, %v", goaway, err)
				}
				pool.Retire(srv)
				pool.mu.Lock()
				retained := len(pool.entries)
				pool.mu.Unlock()
				if retained != 1 {
					t.Fatalf("rotation %d: accepted pool lease membership = %d, want 1", rotation, retained)
				}
				var headers bytes.Buffer
				if err := hpack.NewEncoder(&headers).WriteField(hpack.HeaderField{Name: ":status", Value: "204"}); err != nil {
					t.Fatal(err)
				}
				if err := serverEngine.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: headers.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
					t.Fatal(err)
				}
				if err := peer.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				response, err := clientEngine.ReceiveStream(ctx, identity)
				if err != nil || !response.EndStream {
					t.Fatalf("accepted response = %+v, %v", response, err)
				}
				await(t, clientDone)
				await(t, serverDone)
				cancel()
				pool.mu.Lock()
				retained = len(pool.entries)
				pool.mu.Unlock()
				if retained != 0 {
					t.Fatalf("rotation %d: completed pool membership = %d, want 0", rotation, retained)
				}
			}
		})
	}
}

func TestPoolCompletionDuringUpgrade(t *testing.T) {
	dialer := &poolDialer{t: t}
	pool, _ := newPool(t, dialer.dial)
	_, srv, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = pool.Upgrade(t.Context(), srv, func(_ context.Context, conn layer.Conn, _ *connection.Server) (layer.Conn, error) {
		return conn, conn.Close()
	})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed successful upgrade = %v", err)
	}
	pool.workers.Wait()
	pool.mu.Lock()
	retained := len(pool.entries)
	pool.mu.Unlock()
	if retained != 0 {
		t.Fatalf("completed upgrade membership = %d, want 0", retained)
	}
}

func TestPoolEvictionWaitsForTerminalBookkeeping(t *testing.T) {
	barrier := &poolEndBarrier{entered: make(chan struct{}), release: make(chan struct{})}
	dialer := &poolDialer{t: t}
	pool, _ := newPool(t, dialer.dial, barrier)
	t.Cleanup(func() {
		select {
		case <-barrier.release:
		default:
			close(barrier.release)
		}
	})
	conn, srv, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{Reuse: true})
	if err != nil {
		t.Fatal(err)
	}
	pool.Retire(srv)
	done := make(chan error, 1)
	go func() { done <- conn.Close() }()
	await(t, barrier.entered)
	pool.mu.Lock()
	retained := len(pool.entries)
	pool.mu.Unlock()
	if retained != 1 {
		t.Fatalf("unfinished end hook membership = %d, want 1", retained)
	}
	close(barrier.release)
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	pool.mu.Lock()
	retained = len(pool.entries)
	pool.mu.Unlock()
	if retained != 0 {
		t.Fatalf("completed end hook membership = %d, want 0", retained)
	}
}
