// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"time"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

const (
	// GoAwayFlushGrace bounds shutdown writes to an unresponsive peer.
	GoAwayFlushGrace = time.Second
	// InitialStreamWindow is the advertised per-stream receive window.
	InitialStreamWindow = 1 << 20
	// MaxStreamWindow caps growth of one stream's receive reservation.
	MaxStreamWindow = 16 << 20
	// MaxConcurrentStreams bounds simultaneously reserved streams.
	MaxConcurrentStreams = 100
	// ChunkSize is the capacity of each ownership-transferred receive chunk.
	ChunkSize = 1 << 17
	// MaxFrameSize is the advertised maximum inbound frame size.
	MaxFrameSize = 1 << 17
)

type streamWindow struct {
	grant     int
	available int
	consumed  int
}

type windowBudget struct {
	granted int64
	maximum int64
	streams int
}

func (b *windowBudget) assert() {
	if b.granted < 0 || b.granted > layer.ReceiveBudgetBytes {
		panic("h2: receive reservation invariant violated")
	}
	b.maximum = max(b.maximum, b.granted)
}

func (b *windowBudget) reserve(w *streamWindow) bool {
	if b.streams >= MaxConcurrentStreams || b.granted+InitialStreamWindow > layer.ReceiveBudgetBytes {
		return false
	}
	w.grant, w.available = InitialStreamWindow, InitialStreamWindow
	b.streams++
	b.granted += InitialStreamWindow
	b.assert()
	return true
}

func (b *windowBudget) consume(w *streamWindow, original int) int {
	w.available += original
	w.consumed += original
	growth := 0
	if w.consumed >= w.grant/2 {
		w.consumed = 0
		headroom := int(layer.ReceiveBudgetBytes) - MaxConcurrentStreams*InitialStreamWindow - (int(b.granted) - b.streams*InitialStreamWindow)
		growth = min(w.grant, MaxStreamWindow-w.grant, headroom)
		w.grant += growth
		w.available += growth
		b.granted += int64(growth)
	}
	b.assert()
	return original + growth
}

func (b *windowBudget) release(w *streamWindow) {
	if w.grant == 0 {
		return
	}
	b.granted -= int64(w.grant)
	b.streams--
	*w = streamWindow{}
	b.assert()
}

func (b *windowBudget) snapshot() layer.BudgetSnapshot {
	return layer.BudgetSnapshot{Granted: b.granted, Maximum: b.maximum}
}
