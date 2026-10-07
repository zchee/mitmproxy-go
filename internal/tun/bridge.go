// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/zchee/mitmproxy-go/internal/netstack"
)

const (
	maxPacketSize  = 65535
	maxBatchSize   = 128
	packetHeadroom = 10
)

// Serve carries IP packets between dev and stack until cancellation, stack
// shutdown, or a device I/O failure. It takes ownership of dev immediately,
// closes it exactly once, and joins its I/O workers before returning. The caller
// retains ownership of stack. Rejected malformed or excess packets are dropped
// with a rate-limited diagnostic that does not include packet bytes. An already
// cancelled context takes precedence over device errors. Serve never waits for
// a device event or closes stack.
func Serve(ctx context.Context, dev wgtun.Device, stack *netstack.Stack) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(err, dev.Close())
	}
	batch := dev.BatchSize()
	if batch < 1 || batch > maxBatchSize {
		return errors.Join(fmt.Errorf("TUN batch size %d is outside 1..%d", batch, maxBatchSize), dev.Close())
	}
	bridgeCtx, cancel := context.WithCancel(ctx)
	result := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Go(func() { result <- readPackets(dev, stack, batch) })
	workers.Go(func() { result <- writePackets(bridgeCtx, dev, stack) })
	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-result:
	}
	// Closing the device interrupts network I/O; cancelling the private context
	// also releases a writer waiting on an idle caller-owned stack.
	cancel()
	closeErr := dev.Close()
	workers.Wait()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return errors.Join(err, closeErr)
}

func readPackets(dev wgtun.Device, stack *netstack.Stack, batch int) error {
	buffers := make([][]byte, batch)
	for i := range buffers {
		buffers[i] = make([]byte, maxPacketSize)
	}
	sizes := make([]int, batch)
	var lastDiagnostic time.Time
	logger := slog.Default()
	for {
		count, readErr := dev.Read(buffers, sizes, 0)
		overflow := errors.Is(readErr, wgtun.ErrTooManySegments)
		if readErr != nil && !overflow {
			return fmt.Errorf("TUN read() failed: %w", readErr)
		}
		if count < 0 || count > batch || (count == 0 && !overflow) {
			return fmt.Errorf("TUN read packet count %d: %w", count, io.ErrNoProgress)
		}
		for i := range count {
			if sizes[i] < 0 || sizes[i] > maxPacketSize {
				return fmt.Errorf("TUN read returned invalid packet length %d", sizes[i])
			}
			err := stack.Inject(buffers[i][:sizes[i]], nil)
			if err == nil {
				continue
			}
			if errors.Is(err, netstack.ErrStackClosed) {
				return nil
			}
			if !errors.Is(err, netstack.ErrInvalidPacket) && !errors.Is(err, netstack.ErrQueueFull) {
				return fmt.Errorf("TUN packet injection failed: %w", err)
			}
			lastDiagnostic = logPacketDrop(logger, err, time.Now(), lastDiagnostic)
		}
		// wireguard-go preserves the segments that fit and reports the overflow;
		// it explicitly requires continuing reads after this error.
		if overflow {
			lastDiagnostic = logPacketDrop(logger, readErr, time.Now(), lastDiagnostic)
		}
	}
}

func writePackets(ctx context.Context, dev wgtun.Device, stack *netstack.Stack) error {
	buffer := make([]byte, packetHeadroom+maxPacketSize)
	packets := [][]byte{buffer}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case packet, ok := <-stack.Outbound():
			if !ok {
				return nil
			}
			if len(packet) > maxPacketSize {
				return fmt.Errorf("TUN outbound packet length %d exceeds %d", len(packet), maxPacketSize)
			}
			copy(buffer[packetHeadroom:], packet)
			packets[0] = buffer[:packetHeadroom+len(packet)]
			if _, err := dev.Write(packets, packetHeadroom); err != nil {
				return fmt.Errorf("TUN write() failed: %w", err)
			}
		}
	}
}

func logPacketDrop(logger *slog.Logger, err error, now, previous time.Time) time.Time {
	if !previous.IsZero() && now.Sub(previous) < time.Second {
		return previous
	}
	switch {
	case errors.Is(err, netstack.ErrInvalidPacket):
		logger.Error("Skipping invalid packet from tun interface: invalid IP packet")
	case errors.Is(err, netstack.ErrQueueFull):
		logger.Warn("Dropping packet from tun interface: input queue full")
	case errors.Is(err, wgtun.ErrTooManySegments):
		logger.Warn("Dropping excess segments from tun interface")
	}
	return now
}
