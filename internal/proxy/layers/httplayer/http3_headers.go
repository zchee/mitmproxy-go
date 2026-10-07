// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"log/slog"

	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h3"
)

// Upstream HTTP/3 reuses its HTTP/2 pseudo-header parser and formatter.
// py:mitmproxy/proxy/layers/http/_http3.py:26-29,231-255,290-303.
func parseH3RequestHeaders(fields []h3.HeaderField) (*httpmsg.Request, error) {
	request, err := parseH2RequestHeaders(h3AsH2Fields(fields))
	if err == nil {
		request.HTTPVersion = "HTTP/3"
	}
	return request, err
}

func parseH3ResponseHeaders(fields []h3.HeaderField) (*httpmsg.Response, error) {
	response, err := parseH2ResponseHeaders(h3AsH2Fields(fields))
	if err == nil {
		response.HTTPVersion = "HTTP/3"
	}
	return response, err
}

func h3AsH2Fields(fields []h3.HeaderField) []hpack.HeaderField {
	converted := make([]hpack.HeaderField, len(fields))
	for i, field := range fields {
		converted[i] = hpack.HeaderField{Name: field.Name, Value: field.Value}
	}
	return converted
}

func h2AsH3Fields(fields []hpack.HeaderField) []h3.HeaderField {
	converted := make([]h3.HeaderField, len(fields))
	for i, field := range fields {
		converted[i] = h3.HeaderField{Name: field.Name, Value: field.Value}
	}
	return converted
}

func formatH3RequestHeaders(request *httpmsg.Request, normalize bool, logger *slog.Logger) []h3.HeaderField {
	return h2AsH3Fields(formatH2RequestHeaders(request, normalize, logger))
}

func formatH3ResponseHeaders(response *httpmsg.Response, normalize bool, logger *slog.Logger) []h3.HeaderField {
	return h2AsH3Fields(formatH2ResponseHeaders(response, normalize, logger))
}

func h3RegularHeaders(fields []h3.HeaderField) httpmsg.Headers {
	headers := make(httpmsg.Headers, len(fields))
	for i, field := range fields {
		headers[i] = httpmsg.Field{Name: []byte(field.Name), Value: []byte(field.Value)}
	}
	return headers
}

func formatH3Trailers(headers httpmsg.Headers) []h3.HeaderField {
	// Unlike initial heads, upstream forwards trailer names and bytes verbatim.
	// py:mitmproxy/proxy/layers/http/_http3.py:78-81.
	fields := make([]h3.HeaderField, len(headers))
	for i, field := range headers {
		fields[i] = h3.HeaderField{Name: string(field.Name), Value: string(field.Value)}
	}
	return fields
}
