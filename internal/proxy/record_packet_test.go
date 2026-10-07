// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
)

func packetRecorderPeer(t *testing.T, first []byte) (layer.PacketRecorder, *net.UDPConn, *observedPacketRead) {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	observed := observePacketReads(t, socket)
	listener := packettransport.NewListener(t.Context(), observed)
	t.Cleanup(func() { _ = listener.Close() })
	await(t, observed.ready)
	peer, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if err := peer.SetWriteBuffer(layer.PacketQueueBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write(first); err != nil {
		t.Fatal(err)
	}
	if err := await(t, observed.received); err != nil {
		t.Fatal(err)
	}
	conn := awaitTupleAdmission(t, listener)
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return RecordPackets(conn), peer, observed
}

func TestPacketRecorderReplay(t *testing.T) {
	tests := map[string]struct {
		first     []byte
		truncated bool
	}{
		"ordinary packet":               {first: []byte("first")},
		"empty packet":                  {},
		"replays full truncated packet": {first: []byte("truncated"), truncated: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r, peer, _ := packetRecorderPeer(t, test.first)
			peek, _, err := r.PeekPacket()
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(string(test.first), string(peek)); diff != "" {
				t.Fatal(diff)
			}
			if r.BufferedPackets() != 1 {
				t.Fatalf("buffered = %d, want 1", r.BufferedPackets())
			}
			buf := make([]byte, 32)
			if test.truncated {
				buf = buf[:2]
			}
			if _, _, err := r.ReadFrom(buf); err != nil {
				t.Fatal(err)
			}
			if r.BufferedPackets() != 0 {
				t.Fatalf("consumed packet still buffered: %d", r.BufferedPackets())
			}
			if _, err := peer.Write([]byte("peeked")); err != nil {
				t.Fatal(err)
			}
			if _, _, err := r.PeekPacket(); err != nil {
				t.Fatal(err)
			}
			r.StopRecording()
			r.StopRecording()
			if r.BufferedPackets() != 2 {
				t.Fatalf("replay buffered = %d, want 2", r.BufferedPackets())
			}
			if _, err := peer.Write([]byte("live")); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{string(test.first), "peeked", "live"} {
				buf := make([]byte, 32)
				n, _, err := r.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(want, string(buf[:n])); diff != "" {
					t.Fatalf("replayed packet (-want +got):\n%s", diff)
				}
			}
			if r.BufferedPackets() != 0 {
				t.Fatalf("buffered after replay = %d", r.BufferedPackets())
			}
		})
	}
}

func TestPacketRecorderBounds(t *testing.T) {
	tests := map[string]struct {
		size  int
		count int
	}{
		"empty packet count": {count: layer.PacketQueueCapacity},
		"payload byte count": {size: layer.MaxUDPPacketBytes, count: layer.PacketQueueBytes / layer.MaxUDPPacketBytes},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			payload := make([]byte, test.size)
			r, peer, observed := packetRecorderPeer(t, payload)
			if err := r.SetReadDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			for i := range test.count {
				if i > 0 {
					if _, err := peer.Write(payload); err != nil {
						t.Fatal(err)
					}
					if err := await(t, observed.received); err != nil {
						t.Fatalf("packet %d socket delivery: %v", i, err)
					}
				}
				if _, _, err := awaitPacketRead(t, r, nil); err != nil {
					t.Fatalf("packet %d: %v", i, err)
				}
			}
			if _, err := peer.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := await(t, observed.received); err != nil {
				t.Fatal(err)
			}
			if _, _, err := awaitPacketRead(t, r, nil); !errors.Is(err, layer.ErrPacketOverflow) {
				t.Fatalf("recording overflow = %v", err)
			}
		})
	}
}

func TestPacketRecorderRetainsOverflowCause(t *testing.T) {
	r, _, _ := packetRecorderPeer(t, []byte("saved"))
	if _, _, err := r.PeekPacket(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.WriteTo(make([]byte, layer.MaxUDPPacketBytes+1), r.RemoteAddr()); !errors.Is(err, layer.ErrPacketOverflow) {
		t.Fatalf("transport overflow = %v", err)
	}
	if _, _, err := r.ReadFrom(nil); !errors.Is(err, layer.ErrPacketOverflow) {
		t.Fatalf("recorded overflow cause = %v", err)
	}
	if r.BufferedPackets() != 0 {
		t.Fatal("failed tuple retained replay payloads")
	}
}

func TestPacketRecorderClose(t *testing.T) {
	r, _, _ := packetRecorderPeer(t, []byte("saved"))
	if _, _, err := r.PeekPacket(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if r.BufferedPackets() != 0 {
		t.Fatal("close retained recorded packets")
	}
	if _, _, err := r.ReadFrom(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed recorder read = %v", err)
	}
}
