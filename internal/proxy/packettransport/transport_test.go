// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package packettransport

import (
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func newTestListener(t *testing.T) (*Listener, *net.UDPConn) {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
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

func acceptTestTuple(t *testing.T, listener *Listener, peer *net.UDPConn, payload []byte) *TupleConn {
	t.Helper()
	if _, err := peer.Write(payload); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestTuplePackets(t *testing.T) {
	tests := map[string]struct {
		packets [][]byte
		size    int
	}{
		"preserves boundaries":          {packets: [][]byte{[]byte("first"), []byte("second")}, size: 32},
		"empty is not EOF":              {packets: [][]byte{nil, []byte("next")}, size: 32},
		"truncation discards remainder": {packets: [][]byte{[]byte("long"), []byte("next")}, size: 2},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			listener, peer := newTestListener(t)
			conn := acceptTestTuple(t, listener, peer, test.packets[0])
			for _, payload := range test.packets[1:] {
				if _, err := peer.Write(payload); err != nil {
					t.Fatal(err)
				}
			}
			if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			for _, payload := range test.packets {
				buf := make([]byte, test.size)
				n, addr, err := conn.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				want := payload[:min(len(payload), len(buf))]
				if diff := cmp.Diff(string(want), string(buf[:n])); diff != "" {
					t.Fatalf("packet (-want +got):\n%s", diff)
				}
				if addr.String() != peer.LocalAddr().String() {
					t.Fatalf("peer = %v, want %v", addr, peer.LocalAddr())
				}
			}
			if _, err := conn.WriteTo(nil, conn.RemoteAddr()); err != nil {
				t.Fatal(err)
			}
			if err := peer.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 8)
			if n, err := peer.Read(buf); n != 0 || err != nil {
				t.Fatalf("empty reply = (%d, %v)", n, err)
			}
		})
	}
}

func TestTupleIsolationAndReuse(t *testing.T) {
	listener, peer := newTestListener(t)
	first := acceptTestTuple(t, listener, peer, []byte("one"))
	other, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	second := acceptTestTuple(t, listener, other, []byte("two"))
	if first == second {
		t.Fatal("distinct peers share tuple")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.ReadFrom(make([]byte, 8)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed read = %v", err)
	}
	if err := second.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, _, err := second.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "two" {
		t.Fatalf("isolated read = (%q, %v)", buf[:n], err)
	}
	reused := acceptTestTuple(t, listener, peer, []byte("new"))
	if reused == first {
		t.Fatal("evicted tuple reused old connection")
	}
}

func TestTupleDeadlines(t *testing.T) {
	listener, peer := newTestListener(t)
	conn := acceptTestTuple(t, listener, peer, nil)
	if _, _, err := conn.ReadFrom(nil); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.ReadFrom(nil); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read deadline = %v", err)
	}
	if _, err := conn.WriteTo([]byte("ok"), conn.RemoteAddr()); err != nil {
		t.Fatalf("read deadline affected write: %v", err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo(nil, conn.RemoteAddr()); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write deadline = %v", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("reset")); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if n, _, err := conn.ReadFrom(buf); err != nil || string(buf[:n]) != "reset" {
		t.Fatalf("reset read = (%q, %v)", buf[:n], err)
	}
}

func TestTupleBounds(t *testing.T) {
	tests := map[string]struct {
		count     int
		size      int
		aggregate bool
	}{
		"tuple count":    {count: layer.PacketQueueCapacity + 1, size: 0},
		"tuple bytes":    {count: layer.PacketQueueBytes/layer.MaxUDPPacketBytes + 1, size: layer.MaxUDPPacketBytes},
		"listener count": {count: layer.ListenerPacketQueueCapacity, size: 0, aggregate: true},
		"listener bytes": {count: layer.ListenerPacketQueueBytes / layer.MaxUDPPacketBytes, size: layer.MaxUDPPacketBytes, aggregate: true},
		"oversized":      {count: 1, size: layer.MaxUDPPacketBytes + 1},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			listener, peer := newTestListener(t)
			conn := acceptTestTuple(t, listener, peer, nil)
			if _, _, err := conn.ReadFrom(nil); err != nil {
				t.Fatal(err)
			}
			listener.mu.Lock()
			if test.aggregate {
				payload := make([]byte, test.size)
				perTuple := min(layer.PacketQueueCapacity, layer.PacketQueueBytes/max(1, test.size))
				var filler *TupleConn
				for i := range test.count {
					if i%perTuple == 0 {
						ctx, cancel := context.WithCancelCause(t.Context())
						key := "budget:" + strconv.Itoa(i)
						filler = &TupleConn{listener: listener, key: key, ctx: ctx, cancel: cancel, wake: make(chan struct{}), peer: peer.LocalAddr()}
						listener.tuples[key] = filler
					}
					if !listener.enqueueLocked(filler, payload) {
						listener.mu.Unlock()
						t.Fatalf("budget rejected packet %d before aggregate bound", i)
					}
				}
				listener.enqueueLocked(conn, payload)
			} else {
				for range test.count {
					if !listener.enqueueLocked(conn, make([]byte, test.size)) {
						break
					}
				}
			}
			listener.mu.Unlock()
			if _, _, err := conn.ReadFrom(nil); !errors.Is(err, layer.ErrPacketOverflow) {
				t.Fatalf("overflow read = %v", err)
			}
			select {
			case <-conn.Context().Done():
			default:
				t.Fatal("overflow did not cancel transport")
			}
		})
	}
}

func TestBlockedReadDeadlineAndParentCancel(t *testing.T) {
	tests := map[string]struct{ deadline bool }{"read deadline": {deadline: true}, "parent cancellation": {}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			socket, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listener := NewListener(ctx, socket)
			t.Cleanup(func() { _ = listener.Close() })
			peer, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = peer.Close() })
			conn := acceptTestTuple(t, listener, peer, nil)
			if _, _, err := conn.ReadFrom(nil); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, _, err := conn.ReadFrom(nil); done <- err }()
			want := error(context.Canceled)
			if test.deadline {
				want = os.ErrDeadlineExceeded
				if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("read error = %v, want %v", err, want)
				}
			case <-time.After(10 * time.Second):
				buf := make([]byte, 1<<20)
				n := runtime.Stack(buf, true)
				t.Fatalf("read failed to wake:\n%s", buf[:n])
			}
		})
	}
}

func TestTupleRejectsDifferentPeerAndClonesAddress(t *testing.T) {
	listener, peer := newTestListener(t)
	conn := acceptTestTuple(t, listener, peer, nil)
	addr := conn.RemoteAddr().(*net.UDPAddr)
	addr.Port++
	if conn.RemoteAddr().String() != peer.LocalAddr().String() {
		t.Fatal("RemoteAddr leaked mutable tuple address")
	}
	if _, err := conn.WriteTo(nil, addr); err == nil {
		t.Fatal("WriteTo accepted a different tuple")
	}
}

func TestListenerShutdownAndCancellation(t *testing.T) {
	tests := map[string]struct{ cancel bool }{"close": {}, "cancel": {cancel: true}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			listener, peer := newTestListener(t)
			conn := acceptTestTuple(t, listener, peer, nil)
			if _, _, err := conn.ReadFrom(nil); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			wg.Go(func() {
				_, _, err := conn.ReadFrom(nil)
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("blocked read = %v", err)
				}
			})
			ctx, cancel := context.WithCancel(t.Context())
			if test.cancel {
				cancel()
				if _, err := listener.Accept(ctx); !errors.Is(err, context.Canceled) {
					t.Fatalf("Accept cancel = %v", err)
				}
			} else {
				cancel()
			}
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			wg.Wait()
			<-conn.Context().Done()
			if _, err := listener.Accept(t.Context()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("closed accept = %v", err)
			}
			listener.mu.Lock()
			defer listener.mu.Unlock()
			if len(listener.tuples) != 0 || listener.queuedPackets != 0 || listener.queuedBytes != 0 {
				t.Fatalf("shutdown retained tuples/packets: %d/%d/%d", len(listener.tuples), listener.queuedPackets, listener.queuedBytes)
			}
		})
	}
}
