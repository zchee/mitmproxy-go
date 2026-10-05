// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"fmt"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/human"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// handleConnect answers an HTTP CONNECT request, as upstream's
// handle_connect: the http_connect hook may answer or kill it, regular mode
// with the eager connection strategy proves the destination is reachable,
// and the synthetic reply never carries headers because header bytes break
// Android emulators proxying non-80 ports. A 2xx establishes the tunnel:
// the stream marks itself established and the layer hands the connection to
// a child chosen by the next-layer loop, or to the upstream proxy. The
// request's end event must still be consumed before handing over its reader.
func (s *httpStream) handleConnect(ctx context.Context, event RequestHeaders) (streamOutput, error) {
	s.connectRequest = true
	var err error
	s.snapshot, err = s.c.Hooks.FireFunc(ctx, func(context.Context) error {
		s.flow.Request = event.Request
		s.flow.Request.RawContent = nil
		return nil
	}, addon.HTTPConnectHook{Flow: s.flow})
	if err != nil {
		return streamOutput{}, err
	}
	if s.snapshot.Killed() {
		// A killed CONNECT fires no error hook, as upstream's
		// check_killed(False) after http_connect.
		s.failed = true
		if err := s.notLive(ctx); err != nil {
			return streamOutput{}, err
		}
		return streamOutput{events: []Event{ResponseProtocolError{ID: s.id, Message: "killed", Code: Kill}}}, nil
	}

	request := s.snapshot.Request
	response := s.snapshot.Response
	var metadata *connection.Server
	if err := s.c.Do(ctx, func(context.Context) error {
		s.c.Data.Server.Address = &connection.Address{Host: request.Host, Port: request.Port}
		metadata = s.c.Data.Server
		return nil
	}); err != nil {
		return streamOutput{}, err
	}

	if response == nil && s.route.mode == modeRegular && s.c.Data.Options.Str("connection_strategy") == "eager" {
		conn, actual, err := s.c.Pool.Open(ctx, metadata, layer.OpenOptions{Reuse: true})
		if err != nil {
			response, err = httpmsg.MakeResponse(502, fmt.Appendf(nil,
				"Cannot connect to %s: %v If you plan to redirect requests away from this server, "+
					"consider setting `connection_strategy` to `lazy` to suppress early connections.",
				human.FormatAddress(request.Host, request.Port), err), nil)
			if err != nil {
				return streamOutput{}, err
			}
		} else {
			s.connectConn, s.connectServer = conn, actual
		}
	}
	if response == nil {
		// No response headers: header bytes break proxying non-80 ports on
		// Android emulators using the -http-proxy option.
		response = &httpmsg.Response{
			HTTPVersion: request.HTTPVersion,
			StatusCode:  200,
			Reason:      "Connection established",
			RawContent:  []byte{},
		}
	}

	established := response.StatusCode >= 200 && response.StatusCode < 300
	var hook addon.Hook = addon.HTTPConnectErrorHook{Flow: s.flow}
	if established {
		hook = addon.HTTPConnectedHook{Flow: s.flow}
	}
	s.snapshot, err = s.c.Hooks.FireFunc(ctx, func(context.Context) error {
		s.flow.Response = response
		return nil
	}, hook)
	if err != nil {
		return streamOutput{}, err
	}
	response = s.snapshot.Response

	var out streamOutput
	endStream := len(response.RawContent) == 0 && response.Trailers == nil
	out.events = append(out.events, ResponseHeaders{ID: s.id, Response: response.Clone(), EndStream: endStream})
	if len(response.RawContent) != 0 {
		out.events = append(out.events, ResponseData{ID: s.id, Data: response.RawContent})
	}
	if response.Trailers != nil {
		out.events = append(out.events, ResponseTrailers{ID: s.id, Trailers: response.Trailers})
	}
	out.events = append(out.events, ResponseEndOfMessage{ID: s.id})

	s.response.headers = true
	s.response.done = true
	if established {
		s.connectEstablished = true
		return out, nil
	}
	if err := s.notLive(ctx); err != nil {
		return streamOutput{}, err
	}
	return out, nil
}
