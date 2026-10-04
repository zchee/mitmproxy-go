// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package eventsequence replays a finished flow as the sequence of hooks
// the proxy fired while the flow was live (mitmproxy's eventsequence). The
// master uses it to feed flows loaded from a file through the addons, and
// script.run uses it to run a script over recorded flows.
package eventsequence

import (
	"fmt"
	"iter"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

// Iterate returns the hooks of f in the order the proxy fires them:
//
//   - HTTP: requestheaders and request when there is a request,
//     responseheaders and response when there is a response, then either
//     websocket_start, one websocket_message per message and websocket_end
//     when the flow upgraded to WebSocket, or error when it has an error.
//   - TCP and UDP: tcp_start or udp_start, one message hook per message,
//     then the error hook when the flow has an error and the end hook
//     otherwise.
//   - DNS: dns_request, dns_response and dns_error, each when the flow has
//     the request, response or error.
//
// As in mitmproxy, iterating changes the flow: its WebSocket, TCP or UDP
// messages are taken out when iteration starts and appended back one per
// message hook, so a handler sees the message the hook is about as the
// last one, exactly as when the flow was live. Iterating the sequence to
// the end restores every message; stopping early leaves the flow with the
// messages appended so far.
//
// Iterate panics when f is not one of the four flow types of package flow,
// as mitmproxy raises TypeError for an unknown flow type.
func Iterate(f flow.Flow) iter.Seq[addon.Hook] {
	switch f := f.(type) {
	case *flow.HTTPFlow:
		return iterateHTTP(f)
	case *flow.TCPFlow:
		return iterateTCP(f)
	case *flow.UDPFlow:
		return iterateUDP(f)
	case *flow.DNSFlow:
		return iterateDNS(f)
	default:
		panic(fmt.Sprintf("eventsequence: Unknown flow type: %T", f))
	}
}

func iterateHTTP(f *flow.HTTPFlow) iter.Seq[addon.Hook] {
	return func(yield func(addon.Hook) bool) {
		if f.Request != nil {
			if !yield(addon.RequestHeadersHook{Flow: f}) || !yield(addon.RequestHook{Flow: f}) {
				return
			}
		}
		if f.Response != nil {
			if !yield(addon.ResponseHeadersHook{Flow: f}) || !yield(addon.ResponseHook{Flow: f}) {
				return
			}
		}
		switch {
		case f.WebSocket != nil:
			queue := f.WebSocket.Messages
			f.WebSocket.Messages = make([]*websocket.Message, 0, len(queue))
			if !yield(addon.WebSocketStartHook{Flow: f}) {
				return
			}
			for _, m := range queue {
				f.WebSocket.Messages = append(f.WebSocket.Messages, m)
				if !yield(addon.WebSocketMessageHook{Flow: f}) {
					return
				}
			}
			yield(addon.WebSocketEndHook{Flow: f})
		case f.Error != nil:
			yield(addon.ErrorHook{Flow: f})
		}
	}
}

func iterateTCP(f *flow.TCPFlow) iter.Seq[addon.Hook] {
	return func(yield func(addon.Hook) bool) {
		queue := f.Messages
		f.Messages = make([]*tcp.Message, 0, len(queue))
		if !yield(addon.TCPStartHook{Flow: f}) {
			return
		}
		for _, m := range queue {
			f.Messages = append(f.Messages, m)
			if !yield(addon.TCPMessageHook{Flow: f}) {
				return
			}
		}
		if f.Error != nil {
			yield(addon.TCPErrorHook{Flow: f})
		} else {
			yield(addon.TCPEndHook{Flow: f})
		}
	}
}

func iterateUDP(f *flow.UDPFlow) iter.Seq[addon.Hook] {
	return func(yield func(addon.Hook) bool) {
		queue := f.Messages
		f.Messages = make([]*udp.Message, 0, len(queue))
		if !yield(addon.UDPStartHook{Flow: f}) {
			return
		}
		for _, m := range queue {
			f.Messages = append(f.Messages, m)
			if !yield(addon.UDPMessageHook{Flow: f}) {
				return
			}
		}
		if f.Error != nil {
			yield(addon.UDPErrorHook{Flow: f})
		} else {
			yield(addon.UDPEndHook{Flow: f})
		}
	}
}

func iterateDNS(f *flow.DNSFlow) iter.Seq[addon.Hook] {
	return func(yield func(addon.Hook) bool) {
		if f.Request != nil && !yield(addon.DNSRequestHook{Flow: f}) {
			return
		}
		if f.Response != nil && !yield(addon.DNSResponseHook{Flow: f}) {
			return
		}
		if f.Error != nil {
			yield(addon.DNSErrorHook{Flow: f})
		}
	}
}
