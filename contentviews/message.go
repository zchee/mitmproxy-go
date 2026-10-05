// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/strutil"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

// ErrUnsupportedMessage indicates a message type not supported by PrettifyMessage.
var ErrUnsupportedMessage = errors.New("unsupported contentview message")

// PrettifyMessage renders an HTTP, TCP, UDP, or WebSocket message. HTTP inputs
// may be *httpmsg.Message, *httpmsg.Request, or *httpmsg.Response. A nil registry
// uses DefaultRegistry. An empty viewName means auto. Positive lineCutoff limits
// text through that many newlines; nonpositive values leave the text uncut.
// Callers pass options.Manager.Int("content_view_lines_cutoff") when appropriate.
// A failed automatic view falls back to Raw; an explicitly requested view's
// failure is displayed as an error. Result.Err preserves either failure and wraps
// ErrUnsupportedMessage for unsupported message types. The input and its flow
// must not be mutated concurrently while this function runs.
func PrettifyMessage(message any, f flow.Flow, viewName string, registry *Registry, lineCutoff int) Result {
	if registry == nil {
		registry = DefaultRegistry
	}
	if viewName == "" {
		viewName = "auto"
	}
	data, metadata, description, err := messageData(message, f)
	if err != nil {
		return Result{Text: err.Error(), SyntaxHighlight: "error", Err: err}
	}
	if data == nil {
		return Result{Text: "Content is missing.", SyntaxHighlight: "error"}
	}
	view, err := registry.GetView(data, metadata, viewName)
	if err != nil {
		return Result{Text: err.Error(), SyntaxHighlight: "error", Description: description, Err: err}
	}
	text, err := prettify(view, data, metadata)
	result := Result{Text: text, SyntaxHighlight: view.SyntaxHighlight(), ViewName: view.Name(), Description: description, Err: err}
	if err != nil {
		logSink().Debug("Contentview failed", "view", view.Name(), "error", err)
		if viewName == "auto" {
			result.Text, _ = (Raw{}).Prettify(data, metadata)
			result.SyntaxHighlight = "none"
			result.ViewName = "Raw"
			result.Description += "[failed to parse as " + view.Name() + "]"
		} else {
			result.Text = fmt.Sprintf("Couldn't parse as %s:\n%s\n", view.Name(), err)
			result.SyntaxHighlight = "error"
		}
	}
	result.Text = strutil.EscapeControlCharacters(result.Text, true)
	if lineCutoff > 0 {
		cut := strutil.CutAfterNLines(result.Text, lineCutoff)
		result.Truncated = len(cut) < len(result.Text)
		result.Text = cut
	}
	return result
}

func prettify(view View, data []byte, metadata Metadata) (text string, err error) {
	defer func() {
		if value := recover(); value != nil {
			var ok bool
			if err, ok = value.(error); !ok {
				err = fmt.Errorf("%v", value)
			}
		}
	}()
	return view.Prettify(data, metadata)
}

func messageData(message any, f flow.Flow) ([]byte, Metadata, string, error) {
	metadata := Metadata{Flow: f}
	switch m := message.(type) {
	case *httpmsg.Request:
		if m != nil {
			metadata.HTTPMessage = &m.Message
			metadata.HTTPRequest = m
		}
	case *httpmsg.Response:
		if m != nil {
			metadata.HTTPMessage = &m.Message
		}
	case *httpmsg.Message:
		metadata.HTTPMessage = m
	case *tcp.Message:
		metadata.TCPMessage = m
		metadata.Protocol = "tcp"
		if m != nil {
			return m.Content, metadata, "", nil
		}
	case *udp.Message:
		metadata.UDPMessage = m
		metadata.Protocol = "udp"
		if m != nil {
			return m.Content, metadata, "", nil
		}
	case *websocket.Message:
		metadata.WebSocketMessage = m
		metadata.Protocol = "websocket"
		if m != nil {
			return m.Content, metadata, "", nil
		}
	case nil:
		return nil, metadata, "", nil
	default:
		return nil, metadata, "", fmt.Errorf("%w %T", ErrUnsupportedMessage, message)
	}
	if m := metadata.HTTPMessage; m != nil {
		metadata.Protocol = "http"
		// Content type parsing is deliberately as permissive as upstream: only
		// the media type, before its first parameter, is passed to the views.
		media, _, _ := strings.Cut(m.Headers.Get("content-type"), ";")
		major, minor, ok := strings.Cut(media, "/")
		if ok {
			metadata.ContentType = strings.TrimSpace(major) + "/" + strings.TrimSpace(minor)
		}
		data, err := m.Content()
		if err != nil {
			return m.RawContent, metadata, "[cannot decode]", nil
		}
		if !bytes.Equal(data, m.RawContent) {
			return data, metadata, "[decoded " + m.Headers.Get("content-encoding") + "]", nil
		}
		return data, metadata, "", nil
	}
	return nil, metadata, "", nil
}
