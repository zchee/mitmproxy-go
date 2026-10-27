// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package packettransport

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func newOverflowListener(t *testing.T) (*Listener, *net.UDPConn) {
	t.Helper()
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	listener := NewListener(t.Context(), socket)
	t.Cleanup(func() { _ = listener.Close() })
	peer, err := net.DialUDP("udp", nil, socket.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	return listener, peer
}

func acceptOverflowTuple(t *testing.T, listener *Listener, peer *net.UDPConn, payload []byte) *TupleConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	type admission struct {
		conn *TupleConn
		err  error
	}
	accepted := make(chan admission, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, err := listener.Accept(ctx)
		accepted <- admission{conn, err}
	}()
	defer func() { cancel(); <-finished }()
	resends := 0
	send := func() {
		if _, err := peer.Write(payload); err != nil {
			t.Fatalf("admission write after %d resends: %v", resends, err)
		}
	}
	send()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case result := <-accepted:
			if result.err != nil {
				t.Fatalf("tuple admission after %d resends: %v", resends, result.err)
			}
			// Retransmitted setup datagrams are not part of the queue workload.
			listener.mu.Lock()
			duplicates := len(result.conn.packets) - 1
			listener.mu.Unlock()
			for range max(duplicates, 0) {
				if _, _, err := result.conn.ReadFrom(nil); err != nil {
					t.Fatalf("admission duplicate after %d resends: %v", resends, err)
				}
			}
			return result.conn
		case <-ticker.C:
			resends++
			send()
		case <-ctx.Done():
			t.Fatalf("tuple admission after %d resends: %v", resends, ctx.Err())
		}
	}
}

func fillTupleQueue(t *testing.T, listener *Listener, conn *TupleConn, size, count int) {
	t.Helper()
	listener.mu.Lock()
	defer listener.mu.Unlock()
	payload := make([]byte, size)
	for i := range count {
		if size > 0 {
			payload[0] = byte(i)
		}
		if !listener.enqueueLocked(conn, payload) {
			t.Fatalf("packet %d rejected before tuple bound", i)
		}
	}
}

func TestTupleQueueOverflowDrops(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct {
			kind string
			size int
		}{
			"per_tuple_packets_survive":       {kind: "receive", size: 1},
			"per_tuple_bytes_survive":         {kind: "receive", size: layer.MaxUDPPacketBytes},
			"per_tuple_write_packets_survive": {kind: "write", size: 1},
			"per_tuple_write_bytes_survive":   {kind: "write", size: layer.MaxUDPPacketBytes},
			"drained_tuple_resumes":           {kind: "drain", size: 1},
			"listener_bound_still_evicts":     {kind: "listener", size: 1},
			"accept_full_still_evicts":        {kind: "accept"},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				listener, peer := newOverflowListener(t)
				conn := acceptOverflowTuple(t, listener, peer, nil)
				if _, _, err := conn.ReadFrom(nil); err != nil {
					t.Fatal(err)
				}
				if tt.kind == "accept" {
					// A distinct owned UDP peer must still be rejected when admission
					// is full, independently of the per-tuple datagram drop policy.
					for range cap(listener.accept) {
						listener.accept <- conn
					}
					other, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = other.Close() })
					if _, err := other.Write([]byte("refused")); err != nil {
						t.Fatal(err)
					}
					awaitPacketSignal(t, listener.overflow, "full accept queue rejection")
					listener.mu.Lock()
					_, retained := listener.tuples[other.LocalAddr().Network()+"\x00"+other.LocalAddr().String()]
					queued, tuples := len(listener.accept), len(listener.tuples)
					listener.mu.Unlock()
					if retained || queued != cap(listener.accept) || tuples != 1 {
						t.Fatalf("full admission retained=%t queued=%d tuples=%d", retained, queued, tuples)
					}
					if err := conn.Context().Err(); err != nil {
						t.Fatalf("rejected peer canceled existing tuple: %v", err)
					}
					return
				}

				count := min(layer.PacketQueueCapacity, layer.PacketQueueBytes/tt.size)
				fillTupleQueue(t, listener, conn, tt.size, count)
				if tt.kind == "listener" {
					// Fill the shared budget with individually valid tuple queues.
					// The target also being full must not hide the listener limit.
					for i := 1; i < layer.ListenerPacketQueueCapacity/layer.PacketQueueCapacity; i++ {
						ctx, cancel := context.WithCancelCause(t.Context())
						key := "shared-budget:" + strconv.Itoa(i)
						filler := &TupleConn{listener: listener, key: key, ctx: ctx, cancel: cancel, wake: make(chan struct{}), peer: peer.LocalAddr()}
						listener.mu.Lock()
						listener.tuples[key] = filler
						listener.mu.Unlock()
						fillTupleQueue(t, listener, filler, 1, layer.PacketQueueCapacity)
					}
					listener.mu.Lock()
					accepted := listener.enqueueLocked(conn, []byte("overflow"))
					remaining := listener.queuedPackets
					listener.mu.Unlock()
					if accepted || remaining != layer.ListenerPacketQueueCapacity-count {
						t.Fatalf("listener overflow accepted=%t queued=%d", accepted, remaining)
					}
					if _, _, err := conn.ReadFrom(nil); !errors.Is(err, layer.ErrPacketOverflow) {
						t.Fatalf("listener-wide overflow read=%v", err)
					}
					if !errors.Is(context.Cause(conn.Context()), layer.ErrPacketOverflow) {
						t.Fatalf("listener-wide overflow cause=%v", context.Cause(conn.Context()))
					}
					return
				}

				// A sustained burst cannot consume another byte or retire the tuple.
				payload := bytes.Repeat([]byte{255}, tt.size)
				for range layer.PacketQueueCapacity {
					if tt.kind == "write" {
						if n, err := conn.WriteTo(payload, conn.RemoteAddr()); n != len(payload) || err != nil {
							t.Fatalf("dropped write=(%d, %v), want (%d, nil)", n, err, len(payload))
						}
					} else {
						listener.mu.Lock()
						accepted := listener.enqueueLocked(conn, payload)
						listener.mu.Unlock()
						if accepted {
							t.Fatal("per-tuple bound admitted newest datagram")
						}
					}
				}
				listener.mu.Lock()
				got := [6]int{len(conn.packets), conn.bytes, listener.queuedPackets, listener.queuedBytes, listener.writePackets, len(listener.writes)}
				retained := listener.tuples[conn.key] == conn
				listener.mu.Unlock()
				want := [6]int{count, count * tt.size, count, count * tt.size, 0, 0}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Fatalf("queue accounting after drops (-want +got):\n%s", diff)
				}
				if !retained || conn.Context().Err() != nil {
					t.Fatalf("drop retired tuple: retained=%t cause=%v", retained, context.Cause(conn.Context()))
				}

				// One flooded peer cannot prevent a different owned peer from
				// being admitted and consuming its own datagram.
				other, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = other.Close() })
				sibling := acceptOverflowTuple(t, listener, other, []byte("healthy"))
				buf := make([]byte, max(tt.size, len("healthy")))
				if n, _, err := sibling.ReadFrom(buf); err != nil || string(buf[:n]) != "healthy" {
					t.Fatalf("unaffected tuple=(%q, %v)", buf[:n], err)
				}
				for i := range count {
					n, _, err := conn.ReadFrom(buf)
					if err != nil || n != tt.size || buf[0] != byte(i) {
						t.Fatalf("retained packet %d=(%d, first=%d, %v)", i, n, buf[0], err)
					}
				}
				if tt.kind == "drain" {
					if _, err := peer.Write([]byte("resumed")); err != nil {
						t.Fatal(err)
					}
					n, _, err := readTestPacket(t, conn, buf)
					if err != nil || string(buf[:n]) != "resumed" {
						t.Fatalf("same tuple after drain=(%q, %v)", buf[:n], err)
					}
				}
				if n, err := conn.WriteTo([]byte("reply"), conn.RemoteAddr()); n != len("reply") || err != nil {
					t.Fatalf("write after drain=(%d, %v)", n, err)
				}
				if n, _, err := readTestPacket(t, peer, buf); err != nil || string(buf[:n]) != "reply" {
					t.Fatalf("real datagram after drain=(%q, %v)", buf[:n], err)
				}
			})
		}
	})
}
