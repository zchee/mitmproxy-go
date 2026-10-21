// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package external

import (
	"bytes"
	"crypto/sha256"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

// EditSession holds a detached edit target. Flow is working data, never live state.
type EditSession struct {
	Target  contract.EditTarget
	Flow    flow.Flow
	Mode    string
	Options contract.DetailOptions
}

// Capture identifies the selected message and fingerprints only affected fields.
// f may be borrowed under dispatch: Capture copies it synchronously and retains no source pointer.
func Capture(f flow.Flow, part string, options contract.DetailOptions) (*EditSession, error) {
	if f == nil {
		return nil, errors.New("No flow selected.") //nolint:staticcheck // Preserve upstream's operator-facing diagnostic.
	}
	if _, ok := f.(*flow.DNSFlow); ok {
		return nil, errors.New("Cannot edit DNS flows yet, please submit a patch.") //nolint:staticcheck // Preserve upstream's unsupported-flow diagnostic.
	}
	mode := ""
	if prefix, tail, ok := strings.Cut(part, " ("); ok && strings.HasSuffix(tail, ")") {
		part, mode = prefix, strings.TrimSuffix(tail, ")")
	}
	s := &EditSession{Flow: f.Copy(), Target: contract.EditTarget{FlowID: f.Common().ID, Part: part, Message: -1}, Mode: mode, Options: options}
	s.Flow.Common().ID = f.Common().ID
	s.Flow.Common().Live = f.Common().Live
	switch f := s.Flow.(type) {
	case *flow.TCPFlow:
		s.Target.Message = len(f.Messages) - 1
	case *flow.UDPFlow:
		s.Target.Message = len(f.Messages) - 1
	case *flow.HTTPFlow:
		if part == "websocket-message" && f.WebSocket != nil {
			s.Target.Message = len(f.WebSocket.Messages) - 1
		}
	}
	fingerprint, err := Fingerprint(s.Flow, s.Target)
	if err != nil {
		return nil, err
	}
	s.Target.Fingerprint = fingerprint
	return s, nil
}

// Fingerprint returns a stable digest of the selected fields and message identity.
func Fingerprint(f flow.Flow, target contract.EditTarget) ([32]byte, error) {
	var value any
	if f == nil || f.Common().ID != target.FlowID {
		return [32]byte{}, errors.New("edit target removed")
	}
	if target.Part == "comment" {
		value = f.Common().Comment
	} else if h, ok := f.(*flow.HTTPFlow); ok && target.Part != "websocket-message" {
		switch target.Part {
		case "url":
			if h.Request == nil {
				return [32]byte{}, errors.New("request missing")
			}
			value = []any{h.Request.Scheme, h.Request.Host, h.Request.Port, h.Request.Path, h.Request.Headers}
		case "path", "query":
			if h.Request == nil {
				return [32]byte{}, errors.New("request missing")
			}
			value = []any{h.Request.Scheme, h.Request.Host, h.Request.Port, h.Request.Path}
		case "cookies", "request-headers":
			if h.Request == nil {
				return [32]byte{}, errors.New("request missing")
			}
			value = h.Request.Headers
		case "response-headers", "set-cookies":
			if h.Response != nil {
				value = h.Response.Headers
			}
		case "request-body", "urlencoded form", "multipart form":
			if h.Request == nil {
				return [32]byte{}, errors.New("request missing")
			}
			value = []any{h.Request.Headers, h.Request.RawContent}
		case "response-body":
			if h.Response != nil {
				value = []any{h.Response.Headers, h.Response.RawContent}
			}
		default:
			return [32]byte{}, fmt.Errorf("unsupported edit part %q", target.Part)
		}
	} else {
		message, err := editMessage(f, target)
		if err != nil {
			return [32]byte{}, err
		}
		switch f := f.(type) {
		case *flow.TCPFlow:
			value = f.Messages[target.Message].GetState()
		case *flow.UDPFlow:
			value = f.Messages[target.Message].GetState()
		case *flow.HTTPFlow:
			value = f.WebSocket.Messages[target.Message].GetState()
		default:
			value = message
		}
	}
	data, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

func editMessage(f flow.Flow, target contract.EditTarget) (any, error) {
	index := target.Message
	switch f := f.(type) {
	case *flow.HTTPFlow:
		switch target.Part {
		case "request-body":
			if f.Request != nil {
				return f.Request, nil
			}
		case "response-body":
			if f.Response != nil {
				return f.Response, nil
			}
		case "websocket-message":
			if f.WebSocket != nil && index >= 0 && index < len(f.WebSocket.Messages) {
				return f.WebSocket.Messages[index], nil
			}
		}
	case *flow.TCPFlow:
		if target.Part == "tcp-message" && index >= 0 && index < len(f.Messages) {
			return f.Messages[index], nil
		}
	case *flow.UDPFlow:
		if target.Part == "udp-message" && index >= 0 && index < len(f.Messages) {
			return f.Messages[index], nil
		}
	}
	return nil, errors.New("edit message missing")
}

// Bytes returns owned raw or interactive-view text for a process editor.
func (s *EditSession) Bytes() ([]byte, error) {
	if s.Target.Part == "comment" {
		return []byte(s.Flow.Common().Comment), nil
	}
	if h, ok := s.Flow.(*flow.HTTPFlow); ok && s.Target.Part == "url" {
		return []byte(h.Request.URL()), nil
	}
	if err := s.ensureResponse(); err != nil {
		return nil, err
	}
	message, err := editMessage(s.Flow, s.Target)
	if err != nil {
		return nil, err
	}
	if s.Mode != "" {
		r := contentviews.PrettifyMessageWithMetadata(message, contentviews.Metadata{Flow: s.Flow, ProtobufDefinitions: s.Options.ProtobufDefinitions}, s.Mode, s.Options.Registry, 0)
		return []byte(r.Text), r.Err
	}
	switch message := message.(type) {
	case *httpmsg.Request:
		return bytes.Clone(message.ContentOrRaw()), nil
	case *httpmsg.Response:
		return bytes.Clone(message.ContentOrRaw()), nil
	}
	switch f := s.Flow.(type) {
	case *flow.TCPFlow:
		return bytes.Clone(f.Messages[s.Target.Message].Content), nil
	case *flow.UDPFlow:
		return bytes.Clone(f.Messages[s.Target.Message].Content), nil
	case *flow.HTTPFlow:
		return bytes.Clone(f.WebSocket.Messages[s.Target.Message].Content), nil
	}
	return nil, errors.New("unsupported editor message")
}

func (s *EditSession) ensureResponse() error {
	h, ok := s.Flow.(*flow.HTTPFlow)
	if !ok || h.Response != nil {
		return nil
	}
	switch s.Target.Part {
	case "response-body", "response-headers", "set-cookies":
		response, err := httpmsg.MakeResponse(200, []byte{}, nil)
		if err != nil {
			return err
		}
		h.Response = response
	}
	return nil
}

// PrepareBytes validates edited bytes outside dispatch and returns a non-failing commit.
func (s *EditSession) PrepareBytes(data []byte, strip bool) (contract.Edit, error) {
	data = bytes.Clone(StripNewlines(data, s.Target.Part, strip))
	switch s.Target.Part {
	case "comment":
		s.Flow.Common().Comment = string(data)
	case "url":
		h := s.Flow.(*flow.HTTPFlow)
		if err := h.Request.SetURL(string(data)); err != nil {
			return contract.Edit{}, err
		}
	default:
		if err := s.ensureResponse(); err != nil {
			return contract.Edit{}, err
		}
		if s.Mode != "" {
			registry := s.Options.Registry
			if registry == nil {
				registry = contentviews.DefaultRegistry
			}
			view, ok := registry.Get(s.Mode)
			if !ok {
				return contract.Edit{}, fmt.Errorf("Contentview %s is not bidirectional.", s.Mode) //nolint:staticcheck // Preserve upstream's contentview diagnostic.
			}
			interactive, ok := view.(contentviews.InteractiveView)
			if !ok {
				return contract.Edit{}, fmt.Errorf("Contentview %s is not bidirectional.", s.Mode) //nolint:staticcheck // Preserve upstream's contentview diagnostic.
			}
			message, err := editMessage(s.Flow, s.Target)
			if err != nil {
				return contract.Edit{}, err
			}
			metadata := contentviews.Metadata{Flow: s.Flow, ProtobufDefinitions: s.Options.ProtobufDefinitions}
			switch message := message.(type) {
			case *httpmsg.Request:
				metadata.Protocol = "http"
				metadata.HTTPMessage, metadata.HTTPRequest = &message.Message, message
				metadata.OriginalData = bytes.Clone(message.ContentOrRaw())
			case *httpmsg.Response:
				metadata.Protocol = "http"
				metadata.HTTPMessage = &message.Message
				metadata.OriginalData = bytes.Clone(message.ContentOrRaw())
			case *tcp.Message:
				metadata.Protocol, metadata.TCPMessage = "tcp", message
				metadata.OriginalData = bytes.Clone(message.Content)
			case *udp.Message:
				metadata.Protocol, metadata.UDPMessage = "udp", message
				metadata.OriginalData = bytes.Clone(message.Content)
			case *websocket.Message:
				metadata.Protocol, metadata.WebSocketMessage = "websocket", message
				metadata.OriginalData = bytes.Clone(message.Content)
			}
			if metadata.HTTPMessage != nil {
				media, _, _ := strings.Cut(metadata.HTTPMessage.Headers.Get("content-type"), ";")
				metadata.ContentType = strings.TrimSpace(media)
			}
			data, err = interactive.Reencode(string(data), metadata)
			if err != nil {
				return contract.Edit{}, err
			}
		}
		switch f := s.Flow.(type) {
		case *flow.HTTPFlow:
			switch s.Target.Part {
			case "request-body":
				f.Request.SetContent(data)
			case "response-body":
				f.Response.SetContent(data)
			case "websocket-message":
				f.WebSocket.Messages[s.Target.Message].Content = data
			default:
				return contract.Edit{}, errors.New("unsupported byte edit")
			}
		case *flow.TCPFlow:
			f.Messages[s.Target.Message].Content = data
		case *flow.UDPFlow:
			f.Messages[s.Target.Message].Content = data
		}
	}
	return s.Prepared(), nil
}

// Prepared freezes working values into a narrow, non-failing mutation.
func (s *EditSession) Prepared() contract.Edit {
	changed := s.Flow.Copy()
	part := s.Target.Part
	return contract.Edit{Target: s.Target, Fingerprint: Fingerprint, Apply: func(live flow.Flow, target contract.EditTarget) {
		if part == "comment" {
			live.Common().Comment = changed.Common().Comment
			return
		}
		switch dst := live.(type) {
		case *flow.HTTPFlow:
			src := changed.(*flow.HTTPFlow)
			switch part {
			case "url":
				dst.Request.Scheme, dst.Request.Host, dst.Request.Port, dst.Request.Path = src.Request.Scheme, src.Request.Host, src.Request.Port, src.Request.Path
				dst.Request.Headers = src.Request.Headers.Clone()
			case "path", "query":
				dst.Request.Path = src.Request.Path
			case "cookies", "request-headers":
				dst.Request.Headers = src.Request.Headers.Clone()
			case "request-body", "urlencoded form", "multipart form":
				dst.Request.Headers = src.Request.Headers.Clone()
				dst.Request.RawContent = bytes.Clone(src.Request.RawContent)
			case "response-body", "response-headers", "set-cookies":
				if dst.Response == nil {
					dst.Response = src.Response.Clone()
				} else {
					dst.Response.Headers = src.Response.Headers.Clone()
					if part == "response-body" {
						dst.Response.RawContent = bytes.Clone(src.Response.RawContent)
					}
				}
			case "websocket-message":
				dst.WebSocket.Messages[target.Message].Content = bytes.Clone(src.WebSocket.Messages[target.Message].Content)
			}
		case *flow.TCPFlow:
			dst.Messages[target.Message].Content = bytes.Clone(changed.(*flow.TCPFlow).Messages[target.Message].Content)
		case *flow.UDPFlow:
			dst.Messages[target.Message].Content = bytes.Clone(changed.(*flow.UDPFlow).Messages[target.Message].Content)
		}
	}}
}
