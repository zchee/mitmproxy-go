// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"crypto/sha1" // #nosec G505 -- RFC 6455 requires SHA-1 for the public upgrade challenge.
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/http2"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h2"
)

type websocketHandshake struct {
	clientRequest, serverRequest   *httpmsg.Request
	clientResponse, serverResponse *httpmsg.Response
}

func (h websocketHandshake) validate() error {
	for _, pair := range []struct {
		request  *httpmsg.Request
		response *httpmsg.Response
	}{
		{h.clientRequest, h.clientResponse}, {h.serverRequest, h.serverResponse},
	} {
		request, response := pair.request, pair.response
		if request == nil || response == nil || request.Method != "GET" || response.StatusCode != 101 ||
			!strings.EqualFold(request.Headers.Get("Upgrade"), "websocket") ||
			!strings.EqualFold(response.Headers.Get("Upgrade"), "websocket") ||
			!headerToken(request.Headers, "Connection", "upgrade") || !headerToken(response.Headers, "Connection", "upgrade") ||
			request.Headers.Get("Sec-WebSocket-Version") != "13" {
			return errors.New("httplayer: invalid WebSocket upgrade handshake")
		}
		key := request.Headers.Get("Sec-WebSocket-Key")
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(decoded) != 16 {
			return errors.New("httplayer: invalid WebSocket request key")
		}
		// #nosec G401 -- RFC 6455 mandates this public handshake checksum, not a secret hash.
		digest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		if response.Headers.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(digest[:]) {
			return errors.New("httplayer: invalid WebSocket response accept")
		}
	}
	return nil
}

func (s *httpStream) prepareH2C(ctx context.Context) (*h2.UpgradeRequest, error) {
	request := s.snapshot.Request
	var enabled bool
	if err := s.c.Do(ctx, func(context.Context) error {
		enabled = !s.c.Data.Client.TLS && (!s.c.Data.Options.Has("http2") || s.c.Data.Options.Bool("http2"))
		return nil
	}); err != nil {
		return nil, err
	}
	if !enabled || request.HTTPVersion != "HTTP/1.1" {
		return nil, nil
	}
	if s.requestSent || len(request.RawContent) > h2.InitialStreamWindow {
		if s.c.Logger != nil {
			s.c.Logger.InfoContext(ctx, "Ignoring HTTP/2 Upgrade because the request body cannot be seeded within the initial stream window.")
		}
		request.Headers.Del("Upgrade")
		request.Headers.Del("HTTP2-Settings")
		if err := s.c.Do(ctx, func(context.Context) error { s.flow.Request.Headers = request.Headers.Clone(); return nil }); err != nil {
			return nil, err
		}
		return nil, nil
	}
	settings, err := decodeH2CSettings(request)
	if err != nil {
		return nil, err
	}
	converted := request.Clone()
	if converted.Authority == "" {
		converted.Authority = converted.Headers.Get("Host")
	}
	if converted.Authority == "" {
		converted.Authority = net.JoinHostPort(converted.Host, strconv.Itoa(converted.Port))
	}
	converted.Headers.Del("HTTP2-Settings")
	converted.Headers.Del("Host")
	fields := formatH2RequestHeaders(converted, true, s.c.Logger)
	converted.HTTPVersion = "HTTP/2.0"
	i := 0
	for i < len(fields) && fields[i].IsPseudo() {
		i++
	}
	converted.Headers = h2RegularHeaders(fields[i:])
	if err := s.c.Do(ctx, func(context.Context) error { s.flow.Request = converted; return nil }); err != nil {
		return nil, err
	}
	s.snapshot.Request = converted.Clone()
	return &h2.UpgradeRequest{Settings: settings, Headers: fields, Body: converted.RawContent}, nil
}

func decodeH2CSettings(request *httpmsg.Request) ([]byte, error) {
	values := request.Headers.GetAll("HTTP2-Settings")
	if len(values) != 1 || !headerToken(request.Headers, "Connection", "Upgrade") || !headerToken(request.Headers, "Connection", "HTTP2-Settings") {
		return nil, errors.New("invalid HTTP2-Settings upgrade headers")
	}
	settings, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil || len(settings)%6 != 0 {
		return nil, errors.New("invalid HTTP2-Settings upgrade payload")
	}
	for i := 0; i < len(settings); i += 6 {
		setting := http2.Setting{ID: http2.SettingID(binary.BigEndian.Uint16(settings[i : i+2])), Val: binary.BigEndian.Uint32(settings[i+2 : i+6])}
		if err := setting.Valid(); err != nil {
			return nil, fmt.Errorf("invalid HTTP2-Settings upgrade payload: %w", err)
		}
	}
	return settings, nil
}

func headerToken(headers httpmsg.Headers, name, token string) bool {
	for _, line := range headers.GetAll(name) {
		for value := range strings.SplitSeq(line, ",") {
			if strings.EqualFold(strings.TrimSpace(value), token) {
				return true
			}
		}
	}
	return false
}
