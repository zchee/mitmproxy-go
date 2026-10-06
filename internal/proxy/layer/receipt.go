// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layer

import (
	"fmt"
	"sync/atomic"
)

// EndpointID distinguishes protocol endpoints even when stream numbers match.
type EndpointID string

// StreamIdentity is a wire stream number scoped to its receiving endpoint.
// Flow owners retain this identity when routing events to an upstream connection.
type StreamIdentity struct {
	// Endpoint identifies the receiving protocol endpoint.
	Endpoint EndpointID
	// Stream is the endpoint-local wire stream number.
	Stream uint32
}

// EndpointDescriptor is immutable connection metadata published under dispatch.
// It contains no live connection pointer; endpoints select protocol factories
// from a private copy rather than concurrent ALPN fields.
type EndpointDescriptor struct {
	// Identity identifies the protocol endpoint.
	Identity EndpointID
	// ConnectionID identifies the connection backing the endpoint.
	ConnectionID string
	// Protocol is the negotiated application protocol.
	Protocol string
	// FromClient identifies the client's side of the proxy.
	FromClient bool
}

// ReceiveBudgetBytes limits outstanding stream grants for one endpoint's receive
// direction. Each endpoint has its own budget; opposite directions do not share it.
const ReceiveBudgetBytes = 128 << 20

// BudgetSnapshot is an immutable observation of an endpoint owner's grant budget.
// The owner asserts Granted <= ReceiveBudgetBytes on every grant/release and
// publishes this value through synchronization; observers never read live counters.
type BudgetSnapshot struct {
	// Granted is the sum of outstanding stream reservations in bytes.
	Granted int64
	// Maximum is the greatest observed value of Granted.
	Maximum int64
}

// ConsumptionReceipt accounts for original DATA flow-controlled bytes, including
// padding, independently of transformed output length. Complete follows a buffered
// body append, or writing/deliberately dropping all streaming output. Queue
// acceptance is not consumption. Cancellation invalidates outstanding receipts;
// the endpoint owner releases reservations once and never credits a closed stream.
// Exactly one of Complete and Invalidate succeeds, including concurrent calls.
type ConsumptionReceipt interface {
	// OriginalBytes returns the original flow-controlled length, including padding.
	OriginalBytes() int
	// Complete settles consumption once, returning whether this call won.
	Complete() bool
	// Invalidate cancels a receipt once, returning whether this call won.
	Invalidate() bool
}

// Receipt is a concurrently safe, single-settlement consumption notification.
// The endpoint owner processes Done and Consumed without cross-owner callbacks.
// It must not be copied after construction; use NewConsumptionReceipt.
type Receipt struct {
	original int
	state    atomic.Uint32
	done     chan struct{}
}

// NewConsumptionReceipt returns an outstanding receipt for originalBytes,
// including padding. Negative lengths are rejected; zero-byte DATA is valid.
func NewConsumptionReceipt(originalBytes int) (*Receipt, error) {
	if originalBytes < 0 {
		return nil, fmt.Errorf("proxy: negative flow-controlled length %d", originalBytes)
	}
	return &Receipt{original: originalBytes, done: make(chan struct{})}, nil
}

// OriginalBytes returns the original flow-controlled length, never output length.
func (r *Receipt) OriginalBytes() int { return r.original }

// Complete settles a consumed receipt once and wakes its endpoint owner.
func (r *Receipt) Complete() bool { return r.settle(1) }

// Invalidate cancels an outstanding receipt without returning stream credit.
func (r *Receipt) Invalidate() bool { return r.settle(2) }

func (r *Receipt) settle(state uint32) bool {
	if !r.state.CompareAndSwap(0, state) {
		return false
	}
	close(r.done)
	return true
}

// Done closes after consumption or invalidation, waking the endpoint owner.
func (r *Receipt) Done() <-chan struct{} { return r.done }

// Consumed reports a consumption settlement rather than cancellation.
func (r *Receipt) Consumed() bool { return r.state.Load() == 1 }

var _ ConsumptionReceipt = (*Receipt)(nil)
