// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dumper

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/vtcodes"
	"github.com/zchee/mitmproxy-go/websocket"
)

// WebSocketMessage prints the last WebSocket message with its direction and
// opcode, and its content at high detail.
func (d *Dumper) WebSocketMessage(_ context.Context, f *flow.HTTPFlow) error {
	if !d.match(f) || f.WebSocket == nil || len(f.WebSocket.Messages) == 0 {
		return nil
	}
	message := f.WebSocket.Messages[len(f.WebSocket.Messages)-1]
	direction := "<-"
	if message.FromClient {
		direction = "->"
	}
	path := ""
	if f.Request != nil {
		path = f.Request.Path
	}
	text := fmt.Sprintf("%s %s WebSocket %s message %s %s%s", address(f.ClientConn.Peername), direction, strings.ToLower(message.Type.String()), direction, address(f.ServerConn.Address), path)
	if err := d.echo(text, 0, vtcodes.Style{}); err != nil {
		return err
	}
	if d.options.Int("flow_detail") >= 3 {
		return d.echoMessage(message, f)
	}
	return nil
}

// WebSocketEnd prints a normal close or a WebSocket error.
func (d *Dumper) WebSocketEnd(_ context.Context, f *flow.HTTPFlow) error {
	if !d.match(f) || f.WebSocket == nil {
		return nil
	}
	ws := f.WebSocket
	if ws.CloseCode != nil && (*ws.CloseCode == 1000 || *ws.CloseCode == 1001 || *ws.CloseCode == 1005) {
		closedBy := "server"
		if ws.ClosedByClient != nil && *ws.ClosedByClient {
			closedBy = "client"
		}
		reason := "None"
		if ws.CloseReason != nil {
			reason = *ws.CloseReason
		}
		return d.echo(fmt.Sprintf("WebSocket connection closed by %s: %d %s", closedBy, *ws.CloseCode, reason), 0, vtcodes.Style{})
	}
	return d.echo("Error in WebSocket connection to "+address(f.ServerConn.Address)+": WebSocket Error: "+websocketError(ws), 0, vtcodes.Style{FG: "red"})
}

func websocketError(ws *websocket.Data) string {
	code := "None"
	if ws.CloseCode != nil {
		code = strconv.Itoa(*ws.CloseCode)
	}
	text := "UNKNOWN_ERROR=" + code
	if ws.CloseCode != nil {
		if name, ok := closeReasons[*ws.CloseCode]; ok {
			text = name
		}
	}
	if ws.CloseReason != nil && *ws.CloseReason != "" {
		text += " (reason: " + *ws.CloseReason + ")"
	}
	return text
}

// Names are the RFC 6455 and IANA close-code names used by wsproto.CloseReason.
var closeReasons = map[int]string{
	1000: "NORMAL_CLOSURE", 1001: "GOING_AWAY", 1002: "PROTOCOL_ERROR",
	1003: "UNSUPPORTED_DATA", 1005: "NO_STATUS_RCVD", 1006: "ABNORMAL_CLOSURE",
	1007: "INVALID_FRAME_PAYLOAD_DATA", 1008: "POLICY_VIOLATION", 1009: "MESSAGE_TOO_BIG",
	1010: "MANDATORY_EXT", 1011: "INTERNAL_ERROR", 1012: "SERVICE_RESTART",
	1013: "TRY_AGAIN_LATER", 1014: "BAD_GATEWAY", 1015: "TLS_HANDSHAKE_FAILED",
}
