// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	quicgo "github.com/quic-go/quic-go"
	"golang.org/x/net/ipv4"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettest"
)

type queuedWireFixture struct {
	client       *queuedQUICConn
	accepted     *packettest.Transport
	origin       *queuedQUICConn
	originPacket *packettest.Transport
	diagnostics  *closeFixtureDiagnostics
	dialed       atomic.Bool
}

func newQueuedWireFixture(t *testing.T, ctx context.Context, diagnostics *closeFixtureDiagnostics) *queuedWireFixture {
	t.Helper()
	client, accepted, err := packettest.NewPair(ctx, netip.MustParseAddrPort("127.0.0.1:43001"), netip.MustParseAddrPort("127.0.0.1:43002"))
	if err != nil {
		t.Fatal(err)
	}
	originPacket, origin, err := packettest.NewPair(ctx, netip.MustParseAddrPort("127.0.0.1:44001"), netip.MustParseAddrPort("127.0.0.1:44002"))
	if err != nil {
		_ = client.Close()
		_ = accepted.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = accepted.Close(); _ = originPacket.Close(); _ = origin.Close() })
	q := &queuedWireFixture{
		client: newQueuedQUICConn(t, client, diagnostics, "client"), accepted: accepted,
		origin: newQueuedQUICConn(t, origin, diagnostics, "origin"), originPacket: originPacket,
		diagnostics: diagnostics,
	}
	return q
}

func (q *queuedWireFixture) dial(ctx, lifetime context.Context, server *connection.Server) (layer.PacketTransport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := lifetime.Err(); err != nil {
		return nil, err
	}
	if server.Address == nil || server.Address.String() != q.origin.LocalAddr().String() {
		return nil, errors.New("queued QUIC fixture received a different origin")
	}
	if !q.dialed.CompareAndSwap(false, true) {
		return nil, errors.New("queued QUIC fixture origin was already acquired")
	}
	q.diagnostics.record("queued origin acquired local=%v remote=%v", q.originPacket.LocalAddr(), q.originPacket.RemoteAddr())
	return bindQueuedLifetime(lifetime, q.originPacket), nil
}

type queuedLifetimePackets struct {
	*packettest.Transport
	ctx    context.Context
	cancel context.CancelFunc
	joined chan struct{}
}

func bindQueuedLifetime(lifetime context.Context, packets *packettest.Transport) *queuedLifetimePackets {
	ctx, cancel := context.WithCancel(lifetime)
	p := &queuedLifetimePackets{Transport: packets, ctx: ctx, cancel: cancel, joined: make(chan struct{})}
	context.AfterFunc(ctx, func() {
		_ = packets.Close()
		close(p.joined)
	})
	return p
}

func (p *queuedLifetimePackets) Context() context.Context { return p.ctx }

func (p *queuedLifetimePackets) Close() error {
	p.cancel()
	<-p.joined
	return nil
}

// The real descriptor is used only for quic-go's socket capability setup.
// Never embed UDPConn: promoted optimized reads/writes would bypass the queue.
// ReadBatch is explicit because quic-go otherwise unwraps SyscallConn to read.
// Queue input has no IP ancillary metadata; no ECN receipt is fabricated.
type queuedQUICConn struct {
	*packettest.Transport
	control     *net.UDPConn
	diagnostics *closeFixtureDiagnostics
	side        string
	once        sync.Once
	closeErr    error
}

var _ quicgo.OOBCapablePacketConn = (*queuedQUICConn)(nil)

func newQueuedQUICConn(t *testing.T, packets *packettest.Transport, diagnostics *closeFixtureDiagnostics, side string) *queuedQUICConn {
	t.Helper()
	control, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := &queuedQUICConn{Transport: packets, control: control, diagnostics: diagnostics, side: side}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func (p *queuedQUICConn) Close() error {
	p.once.Do(func() { p.closeErr = errors.Join(p.Transport.Close(), p.control.Close()) })
	return p.closeErr
}

func (p *queuedQUICConn) SyscallConn() (syscall.RawConn, error) { return p.control.SyscallConn() }
func (p *queuedQUICConn) SetReadBuffer(bytes int) error         { return p.control.SetReadBuffer(bytes) }

func (p *queuedQUICConn) SetWriteBuffer(bytes int) error { return p.control.SetWriteBuffer(bytes) }

func (p *queuedQUICConn) ReadFrom(data []byte) (int, net.Addr, error) {
	n, addr, err := p.Transport.ReadFrom(data)
	p.diagnostics.record("%s queued reader bytes=%d peer=%v result=%T: %v", p.side, n, addr, err, err)
	return n, addr, err
}

func (p *queuedQUICConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	n, err := p.Transport.WriteTo(data, addr)
	p.diagnostics.record("%s queued actual WriteTo complete bytes=%d/%d peer=%v result=%T: %v", p.side, n, len(data), addr, err, err)
	return n, err
}

func (p *queuedQUICConn) ReadMsgUDP(data, _ []byte) (int, int, int, *net.UDPAddr, error) {
	n, addr, err := p.ReadFrom(data)
	if err != nil {
		return n, 0, 0, nil, err
	}
	p.diagnostics.record("%s queued ReadMsgUDP complete bytes=%d", p.side, n)
	return n, 0, 0, addr.(*net.UDPAddr), nil
}

func (p *queuedQUICConn) ReadBatch(messages []ipv4.Message, _ int) (int, error) {
	if len(messages) == 0 {
		return 0, nil
	}
	message := &messages[0]
	var buffer []byte
	if len(message.Buffers) == 1 {
		buffer = message.Buffers[0]
	} else {
		size := 0
		for _, data := range message.Buffers {
			size += min(len(data), layer.MaxUDPPacketBytes-size)
		}
		buffer = make([]byte, size)
	}
	n, addr, err := p.ReadFrom(buffer)
	if err != nil {
		return 0, err
	}
	if len(message.Buffers) != 1 {
		remaining := buffer[:n]
		for _, data := range message.Buffers {
			copied := copy(data, remaining)
			remaining = remaining[copied:]
		}
	}
	message.N, message.NN, message.Flags, message.Addr = n, 0, 0, addr
	p.diagnostics.record("%s queued ReadBatch complete bytes=%d", p.side, n)
	return 1, nil
}

func (p *queuedQUICConn) WriteMsgUDP(data, oob []byte, addr *net.UDPAddr) (int, int, error) {
	segment, err := queuedSegmentSize(oob)
	if err != nil {
		return 0, 0, err
	}
	n, err := p.writeSegments(data, segment, addr)
	p.diagnostics.record("%s queued WriteMsgUDP complete bytes=%d/%d segment=%d result=%T: %v", p.side, n, len(data), segment, err, err)
	if err != nil {
		return n, 0, err
	}
	return n, len(oob), nil
}

func (p *queuedQUICConn) writeSegments(data []byte, segment int, addr net.Addr) (int, error) {
	if segment == 0 || len(data) == 0 {
		return p.WriteTo(data, addr)
	}
	written := 0
	for len(data) > 0 {
		size := min(segment, len(data))
		n, err := p.WriteTo(data[:size], addr)
		written += n
		if err != nil {
			return written, err
		}
		data = data[size:]
	}
	return written, nil
}

func queuedWireAdapterConformance(t *testing.T) {
	t.Helper()
	tests := map[string]struct{ segment int }{
		"optimized message and batch": {},
		"segmented datagrams":         {segment: 3},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			diagnostics := &closeFixtureDiagnostics{}
			defer diagnostics.report(t)
			left, right, err := packettest.NewPair(t.Context(), netip.MustParseAddrPort("127.0.0.1:45001"), netip.MustParseAddrPort("127.0.0.1:45002"))
			if err != nil {
				t.Fatal(err)
			}
			writer := newQueuedQUICConn(t, left, diagnostics, "adapter writer")
			reader := newQueuedQUICConn(t, right, diagnostics, "adapter reader")
			data := []byte("abcdefgh")
			if test.segment == 0 {
				n, _, err := writer.WriteMsgUDP(data, nil, writer.RemoteAddr().(*net.UDPAddr))
				if err != nil || n != len(data) {
					t.Fatalf("optimized write bytes=%d error=%v", n, err)
				}
			} else if n, err := writeQueuedSegments(writer, data, test.segment, writer.RemoteAddr().(*net.UDPAddr)); err != nil || n != len(data) {
				t.Fatalf("segmented write bytes=%d error=%v", n, err)
			}
			for offset := 0; offset < len(data); {
				var buffer [32]byte
				messages := []ipv4.Message{{Buffers: [][]byte{buffer[:3], buffer[3:]}}}
				n, err := reader.ReadBatch(messages, 0)
				if err != nil || n != 1 {
					t.Fatalf("optimized batch packets=%d error=%v", n, err)
				}
				size := len(data) - offset
				if test.segment > 0 {
					size = min(size, test.segment)
				}
				if diff := gocmp.Diff(string(data[offset:offset+size]), string(buffer[:messages[0].N])); diff != "" {
					t.Fatalf("queued batch datagram (-want +got):\n%s", diff)
				}
				if messages[0].Addr.String() != writer.LocalAddr().String() {
					t.Fatal("optimized reader changed packet identity")
				}
				offset += size
			}
			if _, err := writer.WriteTo(nil, writer.RemoteAddr()); err != nil {
				t.Fatal(err)
			}
			if n, oobn, _, addr, err := reader.ReadMsgUDP(nil, nil); err != nil || n != 0 || oobn != 0 || addr.String() != writer.LocalAddr().String() {
				t.Fatalf("empty optimized datagram bytes=%d ancillary=%d peer=%v error=%v", n, oobn, addr, err)
			}
		})
	}
}
