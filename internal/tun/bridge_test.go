// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/zchee/mitmproxy-go/internal/netstack"
)

func TestServeEchoPackets(t *testing.T) {
	// rs:src/network/tests.rs:785-859 supplies addresses, echo IDs and payload.
	tests := map[string]struct {
		src, dst  netip.Addr
		offset    int
		typeByte  byte
		batch     int
		malformed bool
		segments  bool
	}{
		"success: IPv4": {src: netip.MustParseAddr("10.0.0.1"), dst: netip.MustParseAddr("10.0.0.42"), offset: 20, batch: 1},
		"success: IPv6": {src: netip.MustParseAddr("ca:fe:ca:fe:ca:fe:0:1"), dst: netip.MustParseAddr("ca:fe:ca:fe:ca:fe:0:2"), offset: 40, typeByte: 129, batch: 1},
		"success: malformed packet does not stop device":    {src: netip.MustParseAddr("10.0.0.1"), dst: netip.MustParseAddr("10.0.0.42"), offset: 20, batch: 1, malformed: true},
		"success: segmentation overflow keeps valid prefix": {src: netip.MustParseAddr("10.0.0.1"), dst: netip.MustParseAddr("10.0.0.42"), offset: 20, batch: 1, segments: true},
		"success: native maximum batch":                     {src: netip.MustParseAddr("10.0.0.1"), dst: netip.MustParseAddr("10.0.0.42"), offset: 20, batch: 128},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { goleak.VerifyNone(t) })
			stack := newBridgeStack(t)
			dev, peer := newPipeDevice(t, tt.batch)
			if tt.segments {
				dev.readErr = fmt.Errorf("segmentation overflow: %w", wgtun.ErrTooManySegments)
			}
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			result := make(chan error, 1)
			go func() { result <- Serve(ctx, dev, stack) }()
			if tt.malformed {
				for _, packet := range [][]byte{nil, {0x40}, {0x70, 0, 0, 0}} {
					sendFrame(t, peer, packet)
				}
			}
			for range 2 {
				packet := bridgeEchoPacket(tt.src, tt.dst)
				sendFrame(t, peer, packet)
				reply := receiveFrame(t, peer)
				if len(reply) != len(packet) || reply[tt.offset] != tt.typeByte {
					t.Fatalf("echo reply = %x", reply)
				}
				if diff := cmp.Diff(packet[tt.offset+4:], reply[tt.offset+4:]); diff != "" {
					t.Errorf("echo identifiers and payload (-want +got):\n%s", diff)
				}
				if tt.src.Is4() {
					ip := header.IPv4(reply)
					if ip.SourceAddress() != tcpip.AddrFrom4(tt.dst.As4()) || ip.DestinationAddress() != tcpip.AddrFrom4(tt.src.As4()) || !ip.IsChecksumValid() || checksum.Checksum(reply[20:], 0) != 0xffff {
						t.Errorf("invalid IPv4 echo reply: %x", reply)
					}
				} else {
					ip := header.IPv6(reply)
					if ip.SourceAddress() != tcpip.AddrFrom16(tt.dst.As16()) || ip.DestinationAddress() != tcpip.AddrFrom16(tt.src.As16()) {
						t.Errorf("IPv6 echo addresses were not reversed: %x", reply)
					}
					icmp := header.ICMPv6(reply[40:])
					if got := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: icmp, Src: ip.SourceAddress(), Dst: ip.DestinationAddress()}); got != icmp.Checksum() {
						t.Error("invalid ICMPv6 checksum")
					}
				}
			}
			cancel()
			if err := waitBridge(t, result); !errors.Is(err, context.Canceled) {
				t.Errorf("Serve cancellation = %v", err)
			}
			assertDeviceJoined(t, dev)
			if err := stack.Inject(bridgeEchoPacket(tt.src, tt.dst), nil); err != nil {
				t.Errorf("Serve closed caller-owned stack: %v", err)
			}
		})
	}
}

func TestServeBatchedPackets(t *testing.T) {
	tests := map[string]struct{ batch, count int }{
		"success: two packets":                           {batch: 2, count: 2},
		"success: two packets in native maximum buffers": {batch: 128, count: 2},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { goleak.VerifyNone(t) })
			stack := newBridgeStack(t)
			dev, peer := newPipeDevice(t, tt.batch)
			dev.readBatch = tt.count
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			result := make(chan error, 1)
			go func() { result <- Serve(ctx, dev, stack) }()
			packet := bridgeEchoPacket(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.42"))
			for range tt.count {
				sendFrame(t, peer, packet)
			}
			for range tt.count {
				reply := receiveFrame(t, peer)
				if len(reply) != len(packet) || reply[20] != 0 || !bytes.Equal(packet[24:], reply[24:]) {
					t.Errorf("batched echo reply = %x", reply)
				}
			}
			cancel()
			if err := waitBridge(t, result); !errors.Is(err, context.Canceled) {
				t.Errorf("batched Serve cancellation = %v", err)
			}
			assertDeviceJoined(t, dev)
		})
	}
}

func TestServeLifecycle(t *testing.T) {
	tests := map[string]struct {
		operation string
		canceled  bool
	}{
		"success: stack closes with idle device reader": {operation: "stack"},
		"error: cancellation with blocked read":         {operation: "cancel", canceled: true},
		"error: read failure releases idle writer":      {operation: "peer"},
		"error: cancellation releases blocked writer":   {operation: "blocked writer", canceled: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { goleak.VerifyNone(t) })
			stack := newBridgeStack(t)
			dev, peer := newPipeDevice(t, 1)
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			result := make(chan error, 1)
			go func() { result <- Serve(ctx, dev, stack) }()
			waitSignal(t, dev.readStarted)
			switch tt.operation {
			case "stack":
				if err := stack.Close(); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			case "peer":
				if err := peer.Close(); err != nil {
					t.Fatal(err)
				}
			case "blocked writer":
				sendFrame(t, peer, bridgeEchoPacket(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.42")))
				waitSignal(t, dev.writeStarted)
				cancel()
			}
			err := waitBridge(t, result)
			if tt.canceled && !errors.Is(err, context.Canceled) {
				t.Errorf("cancellation = %v", err)
			}
			if tt.operation == "stack" && err != nil {
				t.Errorf("normal stack stop = %v", err)
			}
			if tt.operation == "peer" && err == nil {
				t.Error("device read failure was discarded")
			}
			assertDeviceJoined(t, dev)
			if tt.operation != "stack" {
				if err := stack.Inject(bridgeEchoPacket(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.42")), nil); err != nil {
					t.Errorf("caller-owned stack was closed: %v", err)
				}
			}
		})
	}
}

func TestServeStartup(t *testing.T) {
	tests := map[string]struct {
		batch    int
		canceled bool
	}{
		"error: canceled before I/O": {batch: 1, canceled: true},
		"error: zero batch":          {},
		"error: oversized batch":     {batch: 129},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			stack := newBridgeStack(t)
			dev, _ := newPipeDevice(t, tt.batch)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.canceled {
				cancel()
			}
			err := Serve(ctx, dev, stack)
			if err == nil {
				t.Fatal("expected startup refusal")
			}
			if tt.canceled && !errors.Is(err, context.Canceled) {
				t.Errorf("startup cancellation = %v", err)
			}
			assertDeviceJoined(t, dev)
			select {
			case <-dev.readStarted:
				t.Error("reader started after startup refusal")
			default:
			}
			select {
			case <-dev.writeStarted:
				t.Error("writer started after startup refusal")
			default:
			}
		})
	}
}

func TestClosedStackTerminatesPacketReader(t *testing.T) {
	stack := newBridgeStack(t)
	if err := stack.Close(); err != nil {
		t.Fatal(err)
	}
	dev, peer := newPipeDevice(t, 1)
	result := make(chan error, 1)
	go func() { result <- readPackets(dev, stack, 1) }()
	sendFrame(t, peer, bridgeEchoPacket(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.42")))
	if err := waitBridge(t, result); err != nil {
		t.Errorf("closed stack reader = %v", err)
	}
	if got := dev.activeReads.Load(); got != 0 {
		t.Errorf("reader did not join: active = %d", got)
	}
}

func TestPacketDropDiagnostics(t *testing.T) {
	// rs:src/packet_sources/tun.rs:142-143 supplies the invalid-packet prefix.
	// Packet bytes are deliberately omitted; the two warning texts are Go-owned.
	tests := map[string]struct {
		err   error
		level string
		text  string
	}{
		"invalid":  {err: fmt.Errorf("untrusted private payload: %w", netstack.ErrInvalidPacket), level: "ERROR", text: "Skipping invalid packet from tun interface:"},
		"full":     {err: fmt.Errorf("admission: %w", netstack.ErrQueueFull), level: "WARN", text: "Dropping packet from tun interface: input queue full"},
		"segments": {err: fmt.Errorf("segmentation: %w", wgtun.ErrTooManySegments), level: "WARN", text: "Dropping excess segments from tun interface"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&output, nil))
			base := time.Unix(1, 0)
			last := logPacketDrop(logger, tt.err, base, time.Time{})
			for _, offset := range []time.Duration{0, time.Nanosecond, time.Second - time.Nanosecond} {
				last = logPacketDrop(logger, tt.err, base.Add(offset), last)
			}
			if got := strings.Count(output.String(), "level="); got != 1 {
				t.Errorf("same interval emitted %d diagnostics, want one: %s", got, output.String())
			}
			_ = logPacketDrop(logger, tt.err, base.Add(time.Second), last)
			if got := strings.Count(output.String(), "level="); got != 2 {
				t.Errorf("new interval emitted total %d diagnostics, want two: %s", got, output.String())
			}
			if strings.Contains(output.String(), "untrusted private payload") {
				t.Errorf("diagnostic leaked wrapped packet detail: %s", output.String())
			}
			if !strings.Contains(output.String(), "level="+tt.level) || !strings.Contains(output.String(), tt.text) {
				t.Errorf("incorrect packet diagnostic: %s", output.String())
			}
		})
	}
}

func newBridgeStack(t *testing.T) *netstack.Stack {
	t.Helper()
	stack, err := netstack.New(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	return stack
}

func bridgeEchoPacket(src, dst netip.Addr) []byte {
	payload := append([]byte{8, 0, 0, 0, 0, 42, 0x7a, 0x69}, []byte("hello world!")...)
	if src.Is4() {
		header.ICMPv4(payload).SetChecksum(^checksum.Checksum(payload, 0))
		packet := make([]byte, 20+len(payload))
		ip := header.IPv4(packet)
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 255, Protocol: 1, SrcAddr: tcpip.AddrFrom4(src.As4()), DstAddr: tcpip.AddrFrom4(dst.As4())})
		ip.SetChecksum(^ip.CalculateChecksum())
		copy(packet[20:], payload)
		return packet
	}
	payload[0] = 128
	icmp := header.ICMPv6(payload)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: icmp, Src: tcpip.AddrFrom16(src.As16()), Dst: tcpip.AddrFrom16(dst.As16())}))
	packet := make([]byte, 40+len(payload))
	header.IPv6(packet).Encode(&header.IPv6Fields{PayloadLength: uint16(len(payload)), TransportProtocol: 58, HopLimit: 255, SrcAddr: tcpip.AddrFrom16(src.As16()), DstAddr: tcpip.AddrFrom16(dst.As16())})
	copy(packet[40:], payload)
	return packet
}
