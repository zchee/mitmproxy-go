// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package h2 implements independent, bounded HTTP/2 protocol endpoints over
// borrowed connections. Each endpoint assembles HEADERS/CONTINUATION with its
// own HPACK decoder and encodes outgoing fields without name normalization.
package h2

import (
	"fmt"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const maxHeaderBytes = 65536

// ProtocolError identifies a connection-level HTTP/2 failure.
type ProtocolError struct {
	// Code is the GOAWAY error code.
	Code http2.ErrCode
	// Message is the upstream-compatible diagnostic.
	Message string
}

// Error returns the protocol diagnostic.
func (e *ProtocolError) Error() string { return e.Message }

// Timeout reports expiry of the fixed preface or HEADERS deadline.
func (e *ProtocolError) Timeout() bool { return strings.HasSuffix(e.Message, " deadline exceeded") }

func protocolError(code http2.ErrCode, message string) error {
	return &ProtocolError{Code: code, Message: message}
}

type headerAssembly struct {
	decoder  *hpack.Decoder
	stream   uint32
	fields   []hpack.HeaderField
	bytes    int
	encoded  int
	validate bool
	err      error
}

func newHeaderAssembly(validate bool) *headerAssembly {
	a := &headerAssembly{validate: validate}
	a.decoder = hpack.NewDecoder(4096, func(field hpack.HeaderField) {
		a.bytes += len(field.Name) + len(field.Value) + 32
		if a.bytes > maxHeaderBytes {
			a.err = protocolError(http2.ErrCodeEnhanceYourCalm, "HTTP/2 header list too large")
			a.decoder.SetEmitEnabled(false)
			return
		}
		a.fields = append(a.fields, field)
	})
	a.decoder.SetMaxStringLength(maxHeaderBytes)
	return a
}

func (a *headerAssembly) fragment(stream uint32, start, end bool, payload []byte) ([]hpack.HeaderField, error) {
	if stream == 0 || (start && a.stream != 0) || (!start && a.stream != stream) {
		return nil, protocolError(http2.ErrCodeProtocol, "Invalid HTTP/2 HEADERS/CONTINUATION order")
	}
	if start {
		a.stream, a.bytes, a.encoded, a.err = stream, 0, 0, nil
		a.fields = nil
		a.decoder.SetEmitEnabled(true)
	}
	a.encoded += len(payload)
	if a.encoded > maxHeaderBytes*2 {
		return nil, protocolError(http2.ErrCodeEnhanceYourCalm, "HTTP/2 header block too large")
	}
	if _, err := a.decoder.Write(payload); err != nil {
		return nil, protocolError(http2.ErrCodeCompression, "HTTP/2 HPACK decoding error: "+err.Error())
	}
	if a.err != nil {
		return nil, a.err
	}
	if !end {
		return nil, nil
	}
	if err := a.decoder.Close(); err != nil {
		return nil, protocolError(http2.ErrCodeCompression, "HTTP/2 HPACK decoding error: "+err.Error())
	}
	fields := a.fields
	a.stream, a.fields = 0, nil
	if a.validate {
		if err := validateFields(fields); err != nil {
			return nil, err
		}
	}
	return fields, nil
}

func validateFields(fields []hpack.HeaderField) error {
	ordinary := false
	seen := make(map[string]bool)
	for _, field := range fields {
		name := field.Name
		if name != strings.ToLower(name) {
			return protocolError(http2.ErrCodeProtocol, fmt.Sprintf("HTTP/2 protocol error: Received uppercase header name b'%s'.", name))
		}
		if name == "" || strings.ContainsAny(name, " \t\r\n") || strings.ContainsAny(field.Value, "\r\n\x00") {
			return protocolError(http2.ErrCodeProtocol, "HTTP/2 protocol error: Invalid header field")
		}
		if field.IsPseudo() {
			if ordinary || seen[name] {
				return protocolError(http2.ErrCodeProtocol, "HTTP/2 protocol error: Duplicate or misplaced HTTP/2 pseudo header: "+name)
			}
			seen[name] = true
		} else {
			ordinary = true
		}
		switch name {
		case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
			return protocolError(http2.ErrCodeProtocol, "HTTP/2 protocol error: Connection-specific header field present")
		case "te":
			if field.Value != "trailers" {
				return protocolError(http2.ErrCodeProtocol, "HTTP/2 protocol error: Invalid TE header")
			}
		}
	}
	return nil
}
