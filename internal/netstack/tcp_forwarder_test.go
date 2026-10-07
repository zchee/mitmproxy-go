// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type tcpPacketPeer struct {
	s        *Stack
	src, dst netip.AddrPort
	seq, ack uint32
	window   uint16
}

func (p *tcpPacketPeer) send(t *testing.T, flags byte, data []byte, info map[string]any) {
	t.Helper()
	segment := make([]byte, 20+len(data))
	binary.BigEndian.PutUint16(segment, p.src.Port())
	binary.BigEndian.PutUint16(segment[2:], p.dst.Port())
	binary.BigEndian.PutUint32(segment[4:], p.seq)
	binary.BigEndian.PutUint32(segment[8:], p.ack)
	segment[12] = 5 << 4
	segment[13] = flags
	binary.BigEndian.PutUint16(segment[14:], p.window)
	copy(segment[20:], data)
	a := tcpip.AddrFromSlice(p.src.Addr().AsSlice())
	b := tcpip.AddrFromSlice(p.dst.Addr().AsSlice())
	binary.BigEndian.PutUint16(segment[16:], ^checksum.Checksum(segment, header.PseudoHeaderChecksum(header.TCPProtocolNumber, a, b, uint16(len(segment)))))
	if err := p.s.Inject(testIPPacket(p.src.Addr(), p.dst.Addr(), 6, segment), info); err != nil {
		t.Fatal(err)
	}
	p.seq += uint32(len(data))
	if flags&byte(header.TCPFlagSyn|header.TCPFlagFin) != 0 {
		p.seq++
	}
}

func (p *tcpPacketPeer) receive(t *testing.T) []byte {
	t.Helper()
	for {
		segment := tcpSegment(t, receiveOutbound(t, p.s))
		if binary.BigEndian.Uint16(segment) == p.dst.Port() && binary.BigEndian.Uint16(segment[2:]) == p.src.Port() {
			return segment
		}
	}
}

func tcpSegment(t *testing.T, packet []byte) []byte {
	t.Helper()
	off := 20
	if packet[0]>>4 == 6 {
		off = 40
	}
	if len(packet) < off+20 {
		t.Fatalf("truncated TCP response: %x", packet)
	}
	return packet[off:]
}

func acceptTCPPeer(t *testing.T, s *Stack, src, dst netip.AddrPort, info map[string]any) (*tcpPacketPeer, *Stream) {
	t.Helper()
	peer := &tcpPacketPeer{s: s, src: src, dst: dst, seq: 1000, window: 65535}
	peer.send(t, byte(header.TCPFlagSyn), nil, info)
	synack := peer.receive(t)
	if synack[13]&byte(header.TCPFlagSyn|header.TCPFlagAck) != byte(header.TCPFlagSyn|header.TCPFlagAck) || binary.BigEndian.Uint32(synack[8:]) != peer.seq {
		t.Fatalf("SYNACK = %x", synack)
	}
	select {
	case <-s.TCPConns():
		t.Fatal("TCP accepted before handshake acknowledgement")
	default:
	}
	peer.ack = binary.BigEndian.Uint32(synack[4:]) + 1
	peer.send(t, byte(header.TCPFlagAck), nil, nil)
	select {
	case stream := <-s.TCPConns():
		return peer, stream
	case <-time.After(30 * time.Second):
		t.Fatal("TCP accept hang detector")
		return nil, nil
	}
}

func TestTCPForwarderPorts(t *testing.T) {
	tests := map[string]struct {
		src, dst netip.AddrPort
		half     bool
	}{
		"tcp_ipv4_connection": {src: netip.MustParseAddrPort("10.0.0.1:1234"), dst: netip.MustParseAddrPort("10.0.0.42:31337")},
		"tcp_ipv6_connection": {src: netip.MustParseAddrPort("[ca:fe:ca:fe:ca:fe:0:1]:1234"), dst: netip.MustParseAddrPort("[ca:fe:ca:fe:ca:fe:0:2]:31337"), half: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, err := New(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			info := map[string]any{"pid": uint32(42), "process_name": "curl", "remote_endpoint": "example.test:443", "original_src": netip.MustParseAddrPort("192.168.86.134:12345"), "original_dst": netip.MustParseAddrPort("0.0.0.0:0")}
			peer, stream := acceptTCPPeer(t, s, tt.src, tt.dst, info)
			for key, want := range info {
				got, ok := stream.GetExtraInfo(key)
				if !ok || !gocmp.Equal(want, got, gocmp.Comparer(func(a, b netip.AddrPort) bool { return a == b })) {
					t.Fatalf("metadata %s = %v, want %v", key, got, want)
				}
			}
			clear(info)
			peer.send(t, byte(header.TCPFlagAck|header.TCPFlagPsh), []byte("hello world!"), nil)
			buf := make([]byte, 12)
			if _, err := io.ReadFull(stream, buf); err != nil || string(buf) != "hello world!" {
				t.Fatalf("TCP read = %q, %v", buf, err)
			}
			if _, err := stream.Write([]byte("HELLO WORLD!")); err != nil {
				t.Fatal(err)
			}
			if tt.half {
				err = stream.CloseWrite()
			} else {
				err = stream.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			var reply []byte
			for {
				seg := tcpSegment(t, receiveOutbound(t, s))
				if seg[13]&byte(header.TCPFlagRst) != 0 {
					t.Fatalf("close emitted RST: %x", seg)
				}
				off := int(seg[12]>>4) * 4
				reply = append(reply, seg[off:]...)
				peer.ack = binary.BigEndian.Uint32(seg[4:]) + uint32(len(seg)-off)
				if seg[13]&byte(header.TCPFlagFin) != 0 {
					peer.ack++
					break
				}
				peer.send(t, byte(header.TCPFlagAck), nil, nil)
			}
			if !bytes.Equal(reply, []byte("HELLO WORLD!")) {
				t.Fatalf("flushed reply = %q", reply)
			}
			peer.send(t, byte(header.TCPFlagAck|header.TCPFlagFin), nil, nil)
		})
	}
}

func TestTCPKeepaliveClock(t *testing.T) {
	tests := map[string]struct{ ipv6 bool }{"IPv4": {}, "IPv6": {ipv6: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			s, err := newStack(t.Context(), clock)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			src := netip.MustParseAddrPort("10.0.0.1:1234")
			dst := netip.MustParseAddrPort("10.0.0.42:31337")
			if tt.ipv6 {
				src = netip.MustParseAddrPort("[2001:db8::1]:1234")
				dst = netip.MustParseAddrPort("[2001:db8::2]:31337")
			}
			peer, _ := acceptTCPPeer(t, s, src, dst, nil)
			clock.Advance(28*time.Second - time.Nanosecond)
			select {
			case p := <-s.Outbound():
				t.Fatalf("packet before keepalive deadline: %x", p)
			default:
			}
			clock.Advance(time.Nanosecond)
			probe := tcpSegment(t, receiveOutbound(t, s))
			if binary.BigEndian.Uint32(probe[4:]) != peer.ack-1 || len(probe) != int(probe[12]>>4)*4 || probe[13] != byte(header.TCPFlagAck) {
				t.Fatalf("keepalive probe = %x", probe)
			}
			peer.send(t, byte(header.TCPFlagAck), nil, nil)
		})
	}
}

func TestTCPIdleClock(t *testing.T) {
	tests := map[string]struct{ refresh bool }{
		"expires at sixty seconds": {},
		"incoming data refresh":    {refresh: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			s, err := newStack(t.Context(), clock)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			peer, stream := acceptTCPPeer(t, s, netip.MustParseAddrPort("10.0.0.1:1234"), netip.MustParseAddrPort("10.0.0.42:31337"), nil)
			clock.Advance(59 * time.Second)
			if stream.ctx.Err() != nil {
				t.Fatal("TCP expired early")
			}
			if tt.refresh {
				peer.send(t, byte(header.TCPFlagAck|header.TCPFlagPsh), []byte("refresh"), nil)
				if _, err := io.ReadFull(stream, make([]byte, 7)); err != nil {
					t.Fatal(err)
				}
				clock.Advance(time.Second)
				if stream.ctx.Err() != nil {
					t.Fatal("incoming data did not refresh TCP expiry")
				}
				clock.Advance(59 * time.Second)
			} else {
				clock.Advance(time.Second)
			}
			if stream.ctx.Err() == nil {
				t.Fatal("TCP did not expire at deadline")
			}
			if _, err := stream.Write([]byte("expired")); !errors.Is(err, context.Canceled) {
				t.Fatalf("expired TCP write = %v", err)
			}
		})
	}
}

func TestTCPSameStackIsolation(t *testing.T) {
	tests := map[string]struct{ ipv6 bool }{"IPv4": {}, "IPv6": {ipv6: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, err := New(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			src := netip.MustParseAddr("10.0.0.1")
			dst := netip.MustParseAddr("10.0.0.42")
			if tt.ipv6 {
				src = netip.MustParseAddr("2001:db8::1")
				dst = netip.MustParseAddr("2001:db8::2")
			}
			_, blocked := acceptTCPPeer(t, s, netip.AddrPortFrom(src, 1234), netip.AddrPortFrom(dst, 31337), nil)
			if _, err := blocked.Write(make([]byte, maxPendingBytes)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			drained := make(chan error, 1)
			go func() { drained <- blocked.Drain(ctx) }()
			peer, healthy := acceptTCPPeer(t, s, netip.AddrPortFrom(src, 1235), netip.AddrPortFrom(dst, 31337), nil)
			if _, err := healthy.Write([]byte("healthy")); err != nil {
				t.Fatal(err)
			}
			if err := healthy.Close(); err != nil {
				t.Fatal(err)
			}
			var reply []byte
			for {
				seg := peer.receive(t)
				if seg[13]&byte(header.TCPFlagRst) != 0 {
					t.Fatal("healthy sibling reset")
				}
				off := int(seg[12]>>4) * 4
				reply = append(reply, seg[off:]...)
				peer.ack = binary.BigEndian.Uint32(seg[4:]) + uint32(len(seg)-off)
				if seg[13]&byte(header.TCPFlagFin) != 0 {
					peer.ack++
					break
				}
				peer.send(t, byte(header.TCPFlagAck), nil, nil)
			}
			if string(reply) != "healthy" {
				t.Fatalf("healthy reply = %q", reply)
			}
			select {
			case err := <-drained:
				t.Fatalf("unacknowledged stream drained: %v", err)
			default:
			}
			cancel()
			if err := <-drained; !errors.Is(err, context.Canceled) {
				t.Fatalf("stalled drain cancellation = %v", err)
			}
			peer.send(t, byte(header.TCPFlagAck|header.TCPFlagFin), nil, nil)
		})
	}
}

func TestTCPBufferedReset(t *testing.T) {
	tests := map[string]struct{ payload string }{"buffer before reset": {payload: "buffered data"}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, err := New(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			peer, stream := acceptTCPPeer(t, s, netip.MustParseAddrPort("10.0.0.1:1234"), netip.MustParseAddrPort("10.0.0.42:31337"), nil)
			peer.send(t, byte(header.TCPFlagAck|header.TCPFlagPsh), []byte(tt.payload), nil)
			// Reading the ACK proves that the data reached the receive buffer first.
			seg := tcpSegment(t, receiveOutbound(t, s))
			if binary.BigEndian.Uint32(seg[8:]) != peer.seq {
				t.Fatalf("data ACK = %x", seg)
			}
			peer.send(t, byte(header.TCPFlagRst|header.TCPFlagAck), nil, nil)
			buf := make([]byte, len(tt.payload))
			if _, err := io.ReadFull(stream, buf); err != nil || string(buf) != tt.payload {
				t.Fatalf("buffered read = %q, %v", buf, err)
			}
			_, err = stream.Read(make([]byte, 1))
			if err == nil || err == io.EOF || !strings.Contains(strings.ToLower(err.Error()), "reset") {
				t.Fatalf("peer reset = %v", err)
			}
		})
	}
}
