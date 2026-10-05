// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package httpmsg holds mitmproxy's HTTP data model: raw header fields,
// requests, responses and the helpers built on them.
//
// The types keep the raw protocol data the proxy saw. Text attributes that
// upstream stores as bytes (method, scheme, authority, path, HTTP version,
// reason) are Go strings holding those bytes unchanged, so non-UTF-8 values
// survive a round trip. Their serialised state matches mitmproxy's flow
// format 21.
package httpmsg

import (
	"fmt"
	"strconv"

	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/internal/stateutil"
)

// Message holds the fields requests and responses share.
type Message struct {
	// HTTPVersion is the protocol version, for example "HTTP/1.1".
	HTTPVersion string
	// Headers are the message headers.
	Headers Headers
	// RawContent is the body as transferred, possibly compressed. Nil means
	// the body is missing, for example because it was streamed; an empty
	// non-nil slice means a present but empty body.
	RawContent []byte
	// Stream forwards the body without buffering it. Set it in requestheaders
	// or responseheaders; changing it in request or response is too late.
	// Stream is runtime configuration and is not saved in the flow state.
	Stream bool
	// StreamFunc, when non-nil, enables streaming regardless of Stream and
	// maps each received chunk to the chunks forwarded to the peer. Set it in
	// requestheaders or responseheaders. It is called once more with an empty
	// chunk at the end, allowing a transform to flush buffered data.
	//
	// The function runs under the dispatch lock, acquired once per chunk.
	// It receives no context and must not change options, call commands or
	// fire hooks: these operations would wait on the lock it already holds.
	// Slow transforms delay hooks on all connections. Stream alone does not
	// acquire the lock for body chunks. StreamFunc is not saved in flow state.
	StreamFunc func(chunk []byte) [][]byte
	// Trailers are the HTTP trailers. Nil means the message has none.
	Trailers Headers
	// TimestampStart is when the headers were received.
	TimestampStart float64
	// TimestampEnd is when the last byte was received.
	TimestampEnd *float64
}

// IsHTTP10 reports whether the message uses HTTP/1.0.
func (m *Message) IsHTTP10() bool { return m.HTTPVersion == "HTTP/1.0" }

// IsHTTP11 reports whether the message uses HTTP/1.1.
func (m *Message) IsHTTP11() bool { return m.HTTPVersion == "HTTP/1.1" }

// IsHTTP2 reports whether the message uses HTTP/2.
func (m *Message) IsHTTP2() bool { return m.HTTPVersion == "HTTP/2.0" }

// IsHTTP3 reports whether the message uses HTTP/3.
func (m *Message) IsHTTP3() bool { return m.HTTPVersion == "HTTP/3" }

// Content returns the body with its Content-Encoding removed. It returns
// nil when the body is missing, and an error when the encoding cannot be
// decoded. A body whose decoded size would exceed the process-global bound
// (see [SetDecodeLimit]) counts as undecodable, with an error wrapping the
// size-limit error of the decoder.
func (m *Message) Content() ([]byte, error) {
	if m.RawContent == nil {
		return nil, nil
	}
	ce := m.Headers.Get("content-encoding")
	if ce == "" {
		return m.RawContent, nil
	}
	return decodeContent(m.RawContent, ce)
}

// ContentOrRaw is like [Message.Content] but returns the raw body instead of
// failing when the Content-Encoding cannot be decoded.
func (m *Message) ContentOrRaw() []byte {
	c, err := m.Content()
	if err != nil {
		return m.RawContent
	}
	return c
}

// SetContent sets the body from uncompressed bytes, encoding it with the
// message's Content-Encoding, and updates Content-Length unless a
// Transfer-Encoding is present. A nil value marks the body as missing.
//
// When the Content-Encoding cannot be applied, the header is removed and
// the body is stored unencoded, as upstream does.
func (m *Message) SetContent(value []byte) {
	if value == nil {
		m.RawContent = nil
		return
	}
	raw := value
	if ce := m.Headers.Get("content-encoding"); ce != "" {
		var err error
		if raw, err = encodeContent(value, ce); err != nil {
			m.Headers.Del("content-encoding")
			raw = value
		}
	}
	m.RawContent = raw
	if !m.Headers.Has("transfer-encoding") {
		m.Headers.Set("content-length", strconv.Itoa(len(raw)))
	}
}

// Text returns the decoded body as text. The character set comes from a
// byte order mark, the Content-Type charset or the media type, falling back
// to Latin-1, as upstream infers it. A missing body gives "". Like
// [Message.Content], it fails for a body whose decoded size would exceed
// the process-global bound.
func (m *Message) Text() (string, error) {
	content, err := m.Content()
	if err != nil || content == nil {
		return "", err
	}
	enc := inferContentEncoding(m.Headers.Get("content-type"), content)
	return decodeText(content, enc)
}

// TextOrRaw is like [Message.Text] but never fails: when the body cannot be
// decoded it returns the body bytes as they are.
func (m *Message) TextOrRaw() string {
	content := m.ContentOrRaw()
	if content == nil {
		return ""
	}
	enc := inferContentEncoding(m.Headers.Get("content-type"), content)
	s, err := decodeText(content, enc)
	if err != nil {
		return string(content)
	}
	return s
}

// SetText sets the body from text, encoded in the character set the
// Content-Type implies. When the text cannot be represented in it, the body
// is written as UTF-8 and the Content-Type charset is updated to say so.
func (m *Message) SetText(text string) {
	ct := m.Headers.Get("content-type")
	enc := inferContentEncoding(ct, nil)
	b, err := encodeText(text, enc)
	if err != nil {
		parsed, ok := parseContentType(ct)
		if !ok {
			parsed = contentType{Type: "text", Subtype: "plain"}
		}
		parsed.setParam("charset", "utf-8")
		m.Headers.Set("content-type", parsed.String())
		b = []byte(text)
	}
	m.SetContent(b)
}

// Decode removes the Content-Encoding: it decodes the body, drops the
// header and updates Content-Length. A missing or empty body is left as it
// is. When strict is false an undecodable body is kept as it is and only
// the header is removed.
func (m *Message) Decode(strict bool) error {
	if len(m.RawContent) == 0 {
		return nil
	}
	decoded, err := m.Content()
	if err != nil {
		if strict {
			return err
		}
		decoded = m.RawContent
	}
	m.Headers.Del("content-encoding")
	m.SetContent(decoded)
	return nil
}

// Encode sets the Content-Encoding to enc and encodes the current raw body
// with it. The body is not decoded first. An encoding that cannot be applied
// is an error, and the header is left removed.
func (m *Message) Encode(enc string) error {
	m.Headers.Set("content-encoding", enc)
	m.SetContent(m.RawContent)
	if !m.Headers.Has("content-encoding") {
		return fmt.Errorf("%w %q", ErrContentEncoding, enc)
	}
	return nil
}

// putState writes the shared fields in upstream's order.
func (m *Message) putState(s *state.Map) {
	s.Set("http_version", []byte(m.HTTPVersion))
	s.Set("headers", m.Headers.state())
	s.Set("content", stateutil.OptBytes(m.RawContent))
	s.Set("trailers", optHeadersState(m.Trailers))
	s.Set("timestamp_start", m.TimestampStart)
	s.Set("timestamp_end", stateutil.Opt(m.TimestampEnd))
}

// readState reads the shared fields.
func (m *Message) readState(d *state.Decoder) {
	m.HTTPVersion = string(d.Bytes("http_version"))
	if v := d.Any("headers"); d.Err() == nil {
		h, err := headersFromState(v)
		if err != nil {
			d.Fail(fmt.Errorf("field %q: %w", "headers", err))
		}
		m.Headers = h
	}
	m.RawContent = d.OptBytes("content")
	if v := d.Any("trailers"); d.Err() == nil && v != nil {
		h, err := headersFromState(v)
		if err != nil {
			d.Fail(fmt.Errorf("field %q: %w", "trailers", err))
		}
		m.Trailers = h
	}
	m.TimestampStart = d.Float("timestamp_start")
	m.TimestampEnd = d.OptFloat("timestamp_end")
}

func (m *Message) clone() Message {
	out := *m
	out.Headers = m.Headers.Clone()
	if m.RawContent != nil {
		out.RawContent = append([]byte{}, m.RawContent...)
	}
	out.Trailers = m.Trailers.Clone()
	if m.TimestampEnd != nil {
		ts := *m.TimestampEnd
		out.TimestampEnd = &ts
	}
	return out
}
