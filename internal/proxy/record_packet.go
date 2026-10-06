// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// RecordPackets wraps transport with bounded whole-datagram recording/replay.
// One owner reads or peeks. Close and deadlines may run concurrently. Recording
// includes complete consumed packets even when ReadFrom truncates its output.
// StopRecording rewinds once; later reads release replayed payloads promptly.
func RecordPackets(transport layer.PacketTransport) layer.PacketRecorder {
	return &packetRecorder{PacketTransport: transport, recording: true}
}

type recordedPacket struct {
	payload []byte
	addr    net.Addr
	err     error
}

type packetRecorder struct {
	layer.PacketTransport
	mu        sync.Mutex
	packets   []recordedPacket
	pos       int
	bytes     int
	recording bool
	closed    bool
}

func (r *packetRecorder) closedErrorLocked() error {
	if r.closed || r.Context().Err() != nil {
		r.packets = nil
		r.pos = 0
		r.bytes = 0
		return errors.Join(net.ErrClosed, r.Context().Err(), context.Cause(r.Context()))
	}
	return nil
}

func (r *packetRecorder) nextPacket() (recordedPacket, error) {
	r.mu.Lock()
	if err := r.closedErrorLocked(); err != nil {
		r.mu.Unlock()
		return recordedPacket{}, err
	}
	if r.pos < len(r.packets) {
		packet := r.packets[r.pos]
		r.mu.Unlock()
		return packet, nil
	}
	if len(r.packets) >= layer.PacketQueueCapacity {
		r.mu.Unlock()
		return recordedPacket{}, layer.ErrPacketOverflow
	}
	r.mu.Unlock()

	window := make([]byte, layer.MaxUDPPacketBytes+1)
	n, addr, err := r.PacketTransport.ReadFrom(window)
	if err != nil && n == 0 {
		return recordedPacket{}, err
	}
	if n > layer.MaxUDPPacketBytes {
		return recordedPacket{}, layer.ErrPacketOverflow
	}
	packet := recordedPacket{payload: slices.Clone(window[:n]), addr: addr, err: err}
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		clone := *udpAddr
		clone.IP = slices.Clone(udpAddr.IP)
		packet.addr = &clone
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.closedErrorLocked(); err != nil {
		return recordedPacket{}, err
	}
	if r.bytes+n > layer.PacketQueueBytes {
		return recordedPacket{}, layer.ErrPacketOverflow
	}
	r.packets = append(r.packets, packet)
	r.bytes += n
	return packet, nil
}

func (r *packetRecorder) ReadFrom(p []byte) (int, net.Addr, error) {
	r.mu.Lock()
	if err := r.closedErrorLocked(); err != nil {
		r.mu.Unlock()
		return 0, nil, err
	}
	live := !r.recording && len(r.packets) == 0
	r.mu.Unlock()
	if live {
		return r.PacketTransport.ReadFrom(p)
	}
	packet, err := r.nextPacket()
	if err != nil {
		return 0, nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.closedErrorLocked(); err != nil {
		return 0, nil, err
	}
	r.pos++
	if !r.recording {
		r.bytes -= len(r.packets[0].payload)
		r.packets[0] = recordedPacket{}
		r.packets = r.packets[1:]
		r.pos = 0
		if len(r.packets) == 0 {
			r.packets = nil
		}
	}
	return copy(p, packet.payload), packet.addr, packet.err
}

func (r *packetRecorder) PeekPacket() ([]byte, net.Addr, error) {
	packet, err := r.nextPacket()
	if err != nil {
		return nil, nil, err
	}
	return packet.payload, packet.addr, packet.err
}

func (r *packetRecorder) BufferedPackets() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closedErrorLocked() != nil {
		return 0
	}
	return len(r.packets) - r.pos
}

func (r *packetRecorder) StopRecording() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.recording {
		r.recording = false
		r.pos = 0
	}
}

func (r *packetRecorder) Close() error {
	r.mu.Lock()
	r.closed = true
	r.packets = nil
	r.pos = 0
	r.bytes = 0
	r.mu.Unlock()
	return r.PacketTransport.Close()
}
