// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package view

import (
	"context"

	"github.com/zchee/mitmproxy-go/flow"
)

// RequestHeaders adds the HTTP flow when its headers arrive.
func (v *View) RequestHeaders(ctx context.Context, f *flow.HTTPFlow) error {
	v.Add(ctx, []flow.Flow{f})
	return nil
}

// Error refreshes an HTTP flow after an error.
func (v *View) Error(ctx context.Context, f *flow.HTTPFlow) error {
	return v.Update(ctx, []flow.Flow{f})
}

// Response refreshes an HTTP flow after its response.
func (v *View) Response(ctx context.Context, f *flow.HTTPFlow) error {
	return v.Update(ctx, []flow.Flow{f})
}

// Intercept refreshes an intercepted flow. The core addon uses Update at runtime.
func (v *View) Intercept(ctx context.Context, f flow.Flow) error {
	return v.Update(ctx, []flow.Flow{f})
}

// Resume refreshes a resumed flow. The core addon uses Update at runtime.
func (v *View) Resume(ctx context.Context, f flow.Flow) error { return v.Update(ctx, []flow.Flow{f}) }

// Kill refreshes a killed flow. The core addon uses Update at runtime.
func (v *View) Kill(ctx context.Context, f flow.Flow) error { return v.Update(ctx, []flow.Flow{f}) }

// TCPStart adds a new TCP flow.
func (v *View) TCPStart(ctx context.Context, f *flow.TCPFlow) error {
	v.Add(ctx, []flow.Flow{f})
	return nil
}

// TCPMessage refreshes a TCP flow after a message.
func (v *View) TCPMessage(ctx context.Context, f *flow.TCPFlow) error {
	return v.Update(ctx, []flow.Flow{f})
}

// TCPError refreshes a TCP flow after an error.
func (v *View) TCPError(ctx context.Context, f *flow.TCPFlow) error {
	return v.Update(ctx, []flow.Flow{f})
}

// TCPEnd refreshes an ended TCP flow.
func (v *View) TCPEnd(ctx context.Context, f *flow.TCPFlow) error {
	return v.Update(ctx, []flow.Flow{f})
}

// UDPStart adds a new UDP flow.
func (v *View) UDPStart(ctx context.Context, f *flow.UDPFlow) error {
	v.Add(ctx, []flow.Flow{f})
	return nil
}

// UDPMessage refreshes a UDP flow after a datagram.
func (v *View) UDPMessage(ctx context.Context, f *flow.UDPFlow) error {
	return v.Update(ctx, []flow.Flow{f})
}

// UDPError refreshes a UDP flow after an error.
func (v *View) UDPError(ctx context.Context, f *flow.UDPFlow) error {
	return v.Update(ctx, []flow.Flow{f})
}

// UDPEnd refreshes an ended UDP flow.
func (v *View) UDPEnd(ctx context.Context, f *flow.UDPFlow) error {
	return v.Update(ctx, []flow.Flow{f})
}

// DNSRequest adds a DNS query flow.
func (v *View) DNSRequest(ctx context.Context, f *flow.DNSFlow) error {
	v.Add(ctx, []flow.Flow{f})
	return nil
}

// DNSResponse refreshes a DNS response flow.
func (v *View) DNSResponse(ctx context.Context, f *flow.DNSFlow) error {
	return v.Update(ctx, []flow.Flow{f})
}

// DNSError refreshes a DNS flow after an error.
func (v *View) DNSError(ctx context.Context, f *flow.DNSFlow) error {
	return v.Update(ctx, []flow.Flow{f})
}
