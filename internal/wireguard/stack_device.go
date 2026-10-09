// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/zchee/mitmproxy-go/internal/netstack"
)

// stackDevice borrows a caller-owned stack and transfers packets, not streams.
type stackDevice struct {
	ctx     context.Context
	cancel  context.CancelFunc
	stack   *netstack.Stack
	engine  *device.Device
	router  *packetRouter
	peer    int
	local   netip.AddrPort
	events  chan tun.Event
	close   sync.Once
	logger  *slog.Logger
	dropped atomic.Uint64
}

var _ tun.Device = (*stackDevice)(nil)

// File is nil because this packet device has no operating-system descriptor.
func (*stackDevice) File() *os.File { return nil }

// Read copies one stack packet behind the caller's WireGuard header headroom.
// Cancellation and stack shutdown interrupt a pending read.
func (t *stackDevice) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	if len(packets) != 1 || len(sizes) < 1 || offset < 0 || offset > len(packets[0]) {
		return 0, io.ErrShortBuffer
	}
	for {
		if t.ctx.Err() != nil {
			return 0, os.ErrClosed
		}
		select {
		case <-t.ctx.Done():
			return 0, os.ErrClosed
		case packet := <-t.router.queues[t.peer]:
			if len(packet) > len(packets[0])-offset {
				t.drop(io.ErrShortBuffer)
				continue
			}
			sizes[0] = copy(packets[0][offset:], packet)
			return 1, nil
		}
	}
}

// Write admits authenticated plaintext packets without waiting for flow handlers.
// Invalid packets and full admission queues are dropped; stack shutdown stops it.
func (t *stackDevice) Write(packets [][]byte, offset int) (int, error) {
	if len(packets) > 1 || offset < 0 {
		return 0, io.ErrShortBuffer
	}
	if t.ctx.Err() != nil {
		return 0, os.ErrClosed
	}
	info := map[string]any{"original_dst": t.local}
	// IpcGet exposes this device's authenticated peer endpoint. Private-key
	// fields are ignored and never passed to diagnostics or tunnel metadata.
	if settings, err := t.engine.IpcGet(); err == nil {
		for line := range strings.SplitSeq(settings, "\n") {
			if text, ok := strings.CutPrefix(line, "endpoint="); ok {
				if address, err := netip.ParseAddrPort(text); err == nil {
					info["original_src"] = address
				}
			}
		}
	}
	for i, packet := range packets {
		if offset > len(packet) {
			return i, io.ErrShortBuffer
		}
		plaintext := packet[offset:]
		source, _, valid := packetAddresses(plaintext)
		if !valid {
			t.drop(netstack.ErrInvalidPacket)
			continue
		}
		// An accepted packet can immediately generate a reply. Publish ownership
		// before the outbound router can consume that reply, but only on admission.
		t.router.mu.Lock()
		err := t.stack.Inject(plaintext, info)
		if err == nil {
			t.router.sources[source] = t.peer
		}
		t.router.mu.Unlock()
		if err != nil {
			if errors.Is(err, netstack.ErrStackClosed) {
				t.cancel()
				return i, os.ErrClosed
			}
			if errors.Is(err, netstack.ErrInvalidPacket) || errors.Is(err, netstack.ErrQueueFull) {
				t.drop(err)
				continue
			}
			t.cancel()
			return i, err
		}
	}
	return len(packets), nil
}

// MTU preserves the userspace network device's upstream 1420-byte default.
func (*stackDevice) MTU() (int, error) { return 1420, nil }

// Name identifies this virtual adapter without creating an OS interface.
func (*stackDevice) Name() (string, error) { return "wireguard", nil }

// Events does not emit link notifications; the server explicitly calls Up.
func (t *stackDevice) Events() <-chan tun.Event { return t.events }

// Close interrupts packet I/O and closes notifications, but never closes the stack.
func (t *stackDevice) Close() error {
	t.close.Do(func() { t.cancel(); close(t.events) })
	return nil
}

// BatchSize stays fixed at one for the packet channel's whole lifetime.
func (*stackDevice) BatchSize() int { return 1 }

func (t *stackDevice) drop(err error) {
	count := t.dropped.Add(1)
	// Logarithmic diagnostics bound log volume without introducing a timer.
	if count&(count-1) == 0 {
		t.logger.Warn("Dropping incoming packet, TCP channel is full.", "error", err, "dropped", count)
	}
}
