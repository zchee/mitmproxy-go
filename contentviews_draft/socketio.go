// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"fmt"
	"strings"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flow"
)

// SocketIO displays Engine.IO and Socket.IO packet names and payloads.
type SocketIO struct{}

// Name returns the view's selection name.
func (SocketIO) Name() string { return "Socket.IO" }

// SyntaxHighlight returns the renderer's syntax name.
func (SocketIO) SyntaxHighlight() string { return "none" }

// RenderPriority selects nonempty Socket.IO WebSocket messages.
func (SocketIO) RenderPriority(data []byte, metadata contentviews.Metadata) float64 {
	f, ok := metadata.Flow.(*flow.HTTPFlow)
	if len(data) != 0 && ok && f != nil && f.WebSocket != nil && f.Request != nil && strings.Contains(f.Request.Path, "/socket.io/?") {
		return 1
	}
	return 0
}

// Prettify shows visible packet types and escaped payloads.
func (SocketIO) Prettify(data []byte, _ contentviews.Metadata) (string, error) {
	if len(data) > maxViewBytes {
		return "", &LimitError{View: "Socket.IO", Stage: "packet", Bound: "input bytes"}
	}
	name, payload, visible, err := parseSocketIO(data)
	if err != nil || !visible {
		return "", err
	}
	budget := &viewBudget{view: "Socket.IO"}
	if err := budget.reserveBytes(len(name)+1, "packet name"); err != nil {
		return "", err
	}
	text, err := escapedViewBytes(payload, budget)
	if err != nil {
		return "", err
	}
	return name + " " + text, nil
}

func parseSocketIO(data []byte) (string, []byte, bool, error) {
	if len(data) == 0 || data[0] < '0' || data[0] > '6' {
		return "", nil, false, fmt.Errorf("invalid Engine.IO packet type")
	}
	engineNames := [...]string{"OPEN", "CLOSE", "PING", "PONG", "MESSAGE", "UPGRADE", "NOOP"}
	engine := data[0] - '0'
	data = data[1:]
	if engine != 4 {
		return "EngineIO." + engineNames[engine], data, engine != 2 && engine != 3, nil
	}
	if len(data) == 0 || data[0] < '0' || data[0] > '6' {
		return "", nil, false, fmt.Errorf("invalid Socket.IO packet type")
	}
	socketNames := [...]string{"CONNECT", "DISCONNECT", "EVENT", "ACK", "CONNECT_ERROR", "BINARY_EVENT", "BINARY_ACK"}
	socket := data[0] - '0'
	return "SocketIO." + socketNames[socket], data[1:], socket != 3 && socket != 6, nil
}
