// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"context"
	"io"
	"net"
)

// PortCandidates selects distinct IPv4 TCP/UDP port numbers without acquiring
// or reserving sockets. It is owned by one caller and is not concurrency-safe.
// A selected number may still be unavailable when the caller binds it.
type PortCandidates struct {
	remaining []int
	choose    func(int) (int, error)
	selected  int
}

// NewPortCandidates waits for the existing shared IPv4 discovery and creates a
// cursor over the TCP/UDP dynamic-range intersection minus both exclusion sets.
// Unavailable bounds use the IANA dynamic range, retaining exclusions only when
// combined exclusion discovery succeeded. Cancellation stops waiting without
// starting another discovery worker. Errors preserve their cause in net.OpError.
func NewPortCandidates(ctx context.Context) (*PortCandidates, error) {
	return newPortCandidates(ctx, pairPortDomain, nil)
}

func newPortCandidates(ctx context.Context, discover func(context.Context) (pairDomain, error), choose func(int) (int, error)) (*PortCandidates, error) {
	if err := ctx.Err(); err != nil {
		return nil, &net.OpError{Op: "select", Net: "tcp4/udp4", Err: err}
	}
	domain, err := discover(ctx)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return nil, &net.OpError{Op: "select", Net: "tcp4/udp4", Err: err}
	}
	if !domain.available && domain.bounds == (portRange{}) {
		domain.bounds = portRange{first: 49152, last: 65535}
	}
	remaining, err := portCandidates(domain)
	if err != nil {
		return nil, &net.OpError{Op: "select", Net: "tcp4/udp4", Err: err}
	}
	return &PortCandidates{remaining: remaining, choose: choose}, nil
}

// Next returns an unexcluded, distinct candidate, at most 64 times per cursor.
// It returns an error wrapping io.EOF when the domain or selection budget is
// exhausted. Cancellation and sampling errors retain their causes in net.OpError.
// Next never acquires a socket; callers own bind order, retries and rollback.
func (c *PortCandidates) Next(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, &net.OpError{Op: "select", Net: "tcp4/udp4", Err: err}
	}
	if c.selected == attempts || len(c.remaining) == 0 {
		return 0, &net.OpError{Op: "select", Net: "tcp4/udp4", Err: io.EOF}
	}
	candidate, err := takePortCandidate(&c.remaining, c.choose)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return 0, &net.OpError{Op: "select", Net: "tcp4/udp4", Err: err}
	}
	c.selected++
	return candidate, nil
}
