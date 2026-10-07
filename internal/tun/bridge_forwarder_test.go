// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"go.uber.org/goleak"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestServeUDPToSocket(t *testing.T) {
	// rs:src/network/tests.rs:395-429 supplies the inner tuples and data exchange.
	tests := map[string]struct{ src, dst netip.AddrPort }{
		"success: IPv4": {src: netip.MustParseAddrPort("10.0.0.1:1234"), dst: netip.MustParseAddrPort("10.0.0.42:31337")},
		"success: IPv6": {src: netip.MustParseAddrPort("[ca:fe:ca:fe:ca:fe:0:1]:1234"), dst: netip.MustParseAddrPort("[ca:fe:ca:fe:ca:fe:0:2]:31337")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { goleak.VerifyNone(t) })
			origin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = origin.Close() })
			if err := origin.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			originDone := make(chan error, 1)
			go func() {
				buffer := make([]byte, 65535)
				n, addr, err := origin.ReadFromUDP(buffer)
				if err == nil {
					_, err = origin.WriteToUDP(bytes.ToUpper(buffer[:n]), addr)
				}
				originDone <- err
			}()
			stack := newBridgeStack(t)
			dev, peer := newPipeDevice(t, 1)
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			bridgeDone := make(chan error, 1)
			go func() { bridgeDone <- Serve(ctx, dev, stack) }()
			payload := []byte("hello world!")
			segment := make([]byte, 8+len(payload))
			binary.BigEndian.PutUint16(segment, tt.src.Port())
			binary.BigEndian.PutUint16(segment[2:], tt.dst.Port())
			binary.BigEndian.PutUint16(segment[4:], uint16(len(segment)))
			copy(segment[8:], payload)
			a := tcpip.AddrFromSlice(tt.src.Addr().AsSlice())
			b := tcpip.AddrFromSlice(tt.dst.Addr().AsSlice())
			value := ^checksum.Checksum(segment, header.PseudoHeaderChecksum(header.UDPProtocolNumber, a, b, uint16(len(segment))))
			if value == 0 {
				value = 0xffff
			}
			binary.BigEndian.PutUint16(segment[6:], value)
			sendFrame(t, peer, bridgeIPPacket(tt.src.Addr(), tt.dst.Addr(), header.UDPProtocolNumber, segment))
			select {
			case transport := <-stack.UDPConns():
				if transport == nil {
					t.Fatal("stack closed before UDP acceptance")
				}
				t.Cleanup(func() { _ = transport.Close() })
				if transport.LocalAddr().String() != tt.dst.String() || transport.RemoteAddr().String() != tt.src.String() {
					t.Errorf("UDP tuple = %v -> %v", transport.RemoteAddr(), transport.LocalAddr())
				}
				if err := transport.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 65535)
				n, client, err := transport.ReadFrom(buffer)
				if err != nil || !bytes.Equal(buffer[:n], payload) {
					t.Fatalf("accepted UDP = %q, %v", buffer[:n], err)
				}
				conn, err := net.DialUDP("udp4", nil, origin.LocalAddr().(*net.UDPAddr))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = conn.Close() })
				if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err := conn.Write(buffer[:n]); err != nil {
					t.Fatal(err)
				}
				n, err = conn.Read(buffer)
				if err != nil {
					bridgeHang(t, "reading UDP origin", err)
				}
				if _, err := transport.WriteTo(buffer[:n], client); err != nil {
					t.Fatal(err)
				}
			case <-time.After(30 * time.Second):
				bridgeHang(t, "accepting UDP transport", nil)
			}
			reply := receiveFrame(t, peer)
			offset := 20
			if tt.src.Addr().Is6() {
				offset = 40
			}
			if len(reply) != offset+8+len(payload) {
				t.Fatalf("UDP reply = %x", reply)
			}
			udp := reply[offset:]
			if binary.BigEndian.Uint16(udp) != tt.dst.Port() || binary.BigEndian.Uint16(udp[2:]) != tt.src.Port() || !bytes.Equal(udp[8:], bytes.ToUpper(payload)) {
				t.Errorf("UDP reply tuple/payload = %x", reply)
			}
			if err := waitBridge(t, originDone); err != nil {
				t.Errorf("UDP origin = %v", err)
			}
			cancel()
			if err := waitBridge(t, bridgeDone); !errors.Is(err, context.Canceled) {
				t.Errorf("UDP Serve cancellation = %v", err)
			}
			assertDeviceJoined(t, dev)
		})
	}
}

func TestServeTCPToSocket(t *testing.T) {
	// rs:src/network/tests.rs:431-783 supplies the inner tuples and upper-case exchange.
	tests := map[string]struct{ src, dst netip.AddrPort }{
		"success: IPv4": {src: netip.MustParseAddrPort("10.0.0.1:1234"), dst: netip.MustParseAddrPort("10.0.0.42:31337")},
		"success: IPv6": {src: netip.MustParseAddrPort("[ca:fe:ca:fe:ca:fe:0:1]:1234"), dst: netip.MustParseAddrPort("[ca:fe:ca:fe:ca:fe:0:2]:31337")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { goleak.VerifyNone(t) })
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			originDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					defer func() { _ = conn.Close() }()
					err = conn.SetDeadline(time.Now().Add(30 * time.Second))
					buffer := make([]byte, len("hello world!"))
					if err == nil {
						_, err = io.ReadFull(conn, buffer)
					}
					if err == nil {
						_, err = conn.Write(bytes.ToUpper(buffer))
					}
				}
				originDone <- err
			}()
			stack := newBridgeStack(t)
			dev, conn := newPipeDevice(t, 1)
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			bridgeDone := make(chan error, 1)
			go func() { bridgeDone <- Serve(ctx, dev, stack) }()
			peer := bridgeTCPPeer{conn: conn, src: tt.src, dst: tt.dst, seq: 1000}
			peer.send(t, byte(header.TCPFlagSyn), nil)
			synack := peer.receive(t)
			if synack[13]&byte(header.TCPFlagSyn|header.TCPFlagAck) != byte(header.TCPFlagSyn|header.TCPFlagAck) || binary.BigEndian.Uint32(synack[8:]) != peer.seq {
				t.Fatalf("SYNACK = %x", synack)
			}
			peer.ack = binary.BigEndian.Uint32(synack[4:]) + 1
			peer.send(t, byte(header.TCPFlagAck), nil)
			relayDone := make(chan error, 1)
			select {
			case stream := <-stack.TCPConns():
				if stream == nil {
					t.Fatal("stack closed before TCP acceptance")
				}
				t.Cleanup(func() { _ = stream.Close() })
				if stream.LocalAddr().String() != tt.dst.String() || stream.RemoteAddr().String() != tt.src.String() {
					t.Errorf("TCP tuple = %v -> %v", stream.RemoteAddr(), stream.LocalAddr())
				}
				if err := stream.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
					t.Fatal(err)
				}
				go func() {
					var dialer net.Dialer
					origin, err := dialer.DialContext(t.Context(), "tcp4", listener.Addr().String())
					if err == nil {
						defer func() { _ = origin.Close() }()
						err = origin.SetDeadline(time.Now().Add(30 * time.Second))
						buffer := make([]byte, len("hello world!"))
						if err == nil {
							_, err = io.ReadFull(stream, buffer)
						}
						if err == nil {
							_, err = origin.Write(buffer)
						}
						if err == nil {
							_, err = io.ReadFull(origin, buffer)
						}
						if err == nil {
							_, err = stream.Write(buffer)
						}
						if err == nil {
							err = stream.Close()
						}
					}
					relayDone <- err
				}()
			case <-time.After(30 * time.Second):
				bridgeHang(t, "accepting TCP stream", nil)
			}
			peer.send(t, byte(header.TCPFlagAck|header.TCPFlagPsh), []byte("hello world!"))
			var response []byte
			fin := false
			for range 32 {
				segment := peer.receive(t)
				if segment[13]&byte(header.TCPFlagRst) != 0 {
					t.Fatalf("TCP source close emitted RST: %x", segment)
				}
				offset := int(segment[12]>>4) * 4
				if offset < 20 || offset > len(segment) {
					t.Fatalf("bad TCP header length: %x", segment)
				}
				response = append(response, segment[offset:]...)
				peer.ack = binary.BigEndian.Uint32(segment[4:]) + uint32(len(segment)-offset)
				fin = segment[13]&byte(header.TCPFlagFin) != 0
				if fin {
					peer.ack++
				}
				peer.send(t, byte(header.TCPFlagAck), nil)
				if fin {
					break
				}
			}
			if !fin || string(response) != "HELLO WORLD!" {
				t.Errorf("TCP socket reply/FIN = %q, %v", response, fin)
			}
			peer.send(t, byte(header.TCPFlagFin|header.TCPFlagAck), nil)
			if err := waitBridge(t, relayDone); err != nil {
				t.Errorf("TCP relay = %v", err)
			}
			if err := waitBridge(t, originDone); err != nil {
				t.Errorf("TCP origin = %v", err)
			}
			cancel()
			if err := waitBridge(t, bridgeDone); !errors.Is(err, context.Canceled) {
				t.Errorf("TCP Serve cancellation = %v", err)
			}
			assertDeviceJoined(t, dev)
		})
	}
}

type bridgeTCPPeer struct {
	conn     net.Conn
	src, dst netip.AddrPort
	seq, ack uint32
}

func (p *bridgeTCPPeer) send(t *testing.T, flags byte, data []byte) {
	t.Helper()
	segment := make([]byte, 20+len(data))
	binary.BigEndian.PutUint16(segment, p.src.Port())
	binary.BigEndian.PutUint16(segment[2:], p.dst.Port())
	binary.BigEndian.PutUint32(segment[4:], p.seq)
	binary.BigEndian.PutUint32(segment[8:], p.ack)
	segment[12] = 5 << 4
	segment[13] = flags
	binary.BigEndian.PutUint16(segment[14:], 65535)
	copy(segment[20:], data)
	a := tcpip.AddrFromSlice(p.src.Addr().AsSlice())
	b := tcpip.AddrFromSlice(p.dst.Addr().AsSlice())
	binary.BigEndian.PutUint16(segment[16:], ^checksum.Checksum(segment, header.PseudoHeaderChecksum(header.TCPProtocolNumber, a, b, uint16(len(segment)))))
	sendFrame(t, p.conn, bridgeIPPacket(p.src.Addr(), p.dst.Addr(), header.TCPProtocolNumber, segment))
	p.seq += uint32(len(data))
	if flags&byte(header.TCPFlagSyn|header.TCPFlagFin) != 0 {
		p.seq++
	}
}

func (p *bridgeTCPPeer) receive(t *testing.T) []byte {
	t.Helper()
	packet := receiveFrame(t, p.conn)
	offset := 20
	if p.src.Addr().Is6() {
		offset = 40
	}
	if len(packet) < offset+20 {
		t.Fatalf("truncated TCP response: %x", packet)
	}
	segment := packet[offset:]
	if binary.BigEndian.Uint16(segment) != p.dst.Port() || binary.BigEndian.Uint16(segment[2:]) != p.src.Port() {
		t.Fatalf("TCP reply tuple = %x", packet)
	}
	return segment
}

func bridgeIPPacket(src, dst netip.Addr, protocol tcpip.TransportProtocolNumber, payload []byte) []byte {
	if src.Is4() {
		packet := make([]byte, 20+len(payload))
		ip := header.IPv4(packet)
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 255, Protocol: uint8(protocol), SrcAddr: tcpip.AddrFrom4(src.As4()), DstAddr: tcpip.AddrFrom4(dst.As4())})
		ip.SetChecksum(^ip.CalculateChecksum())
		copy(packet[20:], payload)
		return packet
	}
	packet := make([]byte, 40+len(payload))
	header.IPv6(packet).Encode(&header.IPv6Fields{PayloadLength: uint16(len(payload)), TransportProtocol: protocol, HopLimit: 255, SrcAddr: tcpip.AddrFrom16(src.As16()), DstAddr: tcpip.AddrFrom16(dst.As16())})
	copy(packet[40:], payload)
	return packet
}
