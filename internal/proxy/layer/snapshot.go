// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layer

import (
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

// Snapshot is the current hook's outbound state, copied under the dispatch
// lock after update handlers finish. It copies only the current message,
// not the flow's accumulated history. A layer must use this snapshot rather
// than reading the live flow after [Hooks.Fire] or [Hooks.FireFunc] returns.
// Mutable data is deep-cloned; function values retain their identity.
// Connection identity fields such as IDs are preserved.
type Snapshot struct {
	// Error is the flow's error, or nil.
	Error *flow.Error
	// Live reports whether the flow belonged to an active connection.
	Live bool
	// Client and Server are copies of the flow's connection metadata.
	Client *connection.Client
	Server *connection.Server
	// Request and Response hold HTTP messages, including partial messages.
	Request  *httpmsg.Request
	Response *httpmsg.Response
	// LastMessage is the newest TCP message, not the accumulated history.
	LastMessage *tcp.Message
	// LastUDPMessage is the newest datagram, including a zero-length datagram.
	LastUDPMessage *udp.Message
	// WebSocket is the HTTP flow's close metadata and newest WebSocket message.
	// Its Messages has at most one entry; it never copies accumulated history.
	WebSocket *websocket.Data
	// NumMessages is the total TCP, UDP or WebSocket message count.
	NumMessages int
}

// Killed reports whether a handler killed the flow. A killed flow must not
// forward its pending data.
func (s *Snapshot) Killed() bool {
	return s != nil && s.Error != nil && s.Error.Msg == flow.KilledMessage
}
