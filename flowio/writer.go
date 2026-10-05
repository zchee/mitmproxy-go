// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowio

import (
	"fmt"
	"io"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
)

// Writer writes flows to a flow file, porting mitmproxy's FlowWriter.
type Writer struct {
	w io.Writer
}

// NewWriter returns a Writer that writes flows to w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// Add writes f in format [flow.FormatVersion]. Each flow is encoded in full
// before anything is written, so an encoding error writes nothing.
//
// Add refuses, and writes nothing for, a flow that lacks a part mitmproxy
// requires and that [Reader] would therefore refuse to read back: an HTTP
// or DNS flow without a request, a flow without a client or server
// connection, a client connection without a peer address, a socket address
// or a start time, and a connection without a transport protocol. Upstream's
// get_state raises for the same flows, whose parts its constructors always
// set. Add does not check that each value is one Reader accepts, such as a
// known TLS version; upstream writes such values without checking too.
func (w *Writer) Add(f flow.Flow) error {
	if missing := missingPart(f); missing != "" {
		return fmt.Errorf("flowio: cannot write %s flow: no %s", f.Type(), missing)
	}
	b, err := tnetstring.Dumps(f.GetState())
	if err != nil {
		return err
	}
	_, err = w.w.Write(b)
	return err
}

// missingPart returns the state name of the first part f lacks that the
// flow's SetState requires, or "" when f has them all. It looks at the
// model, not at the state, because the state of a missing connection is an
// empty one rather than None.
func missingPart(f flow.Flow) string {
	switch f := f.(type) {
	case *flow.HTTPFlow:
		if f.Request == nil {
			return "request"
		}
	case *flow.DNSFlow:
		if f.Request == nil {
			return "request"
		}
	}
	b := f.Common()
	c, s := b.ClientConn, b.ServerConn
	switch {
	case c == nil:
		return "client_conn"
	case s == nil:
		return "server_conn"
	case c.Peername == nil:
		return "client_conn.peername"
	case c.Sockname == nil:
		return "client_conn.sockname"
	case c.TimestampStart == nil:
		return "client_conn.timestamp_start"
	case c.TransportProtocol == "":
		return "client_conn.transport_protocol"
	case s.TransportProtocol == "":
		return "server_conn.transport_protocol"
	}
	return ""
}
