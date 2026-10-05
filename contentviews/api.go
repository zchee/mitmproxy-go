// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package contentviews formats message bodies for display and interactive editing.
// Views must support concurrent calls and must not modify their input or metadata.
package contentviews

import (
	"log/slog"
	"sync/atomic"

	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

// View transforms bytes into human-readable text.
// SyntaxHighlight returns css, javascript, xml, yaml, none, or error.
// RenderPriority selects the automatic view: higher wins, negative means unsupported.
// Prettify returns an error when the data cannot be rendered by this view.
type View interface {
	Name() string
	SyntaxHighlight() string
	Prettify(data []byte, metadata Metadata) (string, error)
	RenderPriority(data []byte, metadata Metadata) float64
}

// InteractiveView also encodes edited text into the original data format.
type InteractiveView interface {
	View
	Reencode(prettified string, metadata Metadata) ([]byte, error)
}

// Metadata describes the data being displayed. Every field is optional.
// The message and flow pointers are borrowed; callers synchronise their access.
type Metadata struct {
	Flow                flow.Flow
	ContentType         string
	HTTPMessage         *httpmsg.Message
	HTTPRequest         *httpmsg.Request
	TCPMessage          *tcp.Message
	UDPMessage          *udp.Message
	WebSocketMessage    *websocket.Message
	DNSMessage          *dns.Message
	Protocol            string
	ProtobufDefinitions string
	OriginalData        []byte
}

// Result contains display text, the selected view, and content-decoding information.
// An empty ViewName means no view could be selected. Truncated reports line cutoff.
type Result struct {
	Text            string
	SyntaxHighlight string
	ViewName        string
	Description     string
	Truncated       bool
}

var logger atomic.Pointer[slog.Logger]

// SetLogger replaces the package logger and returns the previous one.
// A nil logger uses slog.Default. Restore the returned value after temporary use.
func SetLogger(l *slog.Logger) *slog.Logger { return logger.Swap(l) }

func logSink() *slog.Logger {
	if l := logger.Load(); l != nil {
		return l
	}
	return slog.Default()
}
