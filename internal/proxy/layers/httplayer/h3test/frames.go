// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go/quicvarint"
)

// Frame is one decoded wire frame, including control and unknown frames.
type Frame struct {
	Kind    uint64
	Payload []byte
}

// ReadFrame reads a bounded test frame, returning EOF only between frames.
func ReadFrame(reader io.Reader) (Frame, error) {
	var frame Frame
	var err error
	frame.Kind, err = quicvarint.Read(quicvarint.NewReader(reader))
	if err != nil {
		return frame, err
	}
	length, err := quicvarint.Read(quicvarint.NewReader(reader))
	if err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return frame, err
	}
	if length > 1<<20 {
		return frame, fmt.Errorf("test frame payload exceeds limit: %d", length)
	}
	frame.Payload = make([]byte, int(length))
	_, err = io.ReadFull(reader, frame.Payload)
	return frame, err
}

// WriteFrame writes a single HTTP/3 frame to the stream.
func WriteFrame(t *testing.T, writer io.Writer, kind uint64, payload []byte) {
	t.Helper()
	frame := quicvarint.Append(nil, kind)
	frame = quicvarint.Append(frame, uint64(len(payload)))
	frame = append(frame, payload...)
	if _, err := writer.Write(frame); err != nil {
		t.Fatal(err)
	}
}

// WriteHeaders encodes ordered static/literal QPACK fields in a HEADERS frame.
func WriteHeaders(t *testing.T, writer io.Writer, fields []qpack.HeaderField) {
	t.Helper()
	var buffer bytes.Buffer
	encoder := qpack.NewEncoder(&buffer)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	WriteFrame(t, writer, 1, buffer.Bytes())
}

// ReadHeaders reads one HEADERS frame without reading the message body.
func ReadHeaders(t *testing.T, reader io.Reader) []qpack.HeaderField {
	t.Helper()
	frame, err := ReadFrame(reader)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Kind != 1 {
		t.Fatalf("frame type = %d; want HEADERS", frame.Kind)
	}
	return decodeHeaders(t, frame.Payload)
}

func decodeHeaders(t *testing.T, block []byte) []qpack.HeaderField {
	t.Helper()
	decode := qpack.NewDecoder().Decode(block)
	var fields []qpack.HeaderField
	for {
		field, err := decode()
		if errors.Is(err, io.EOF) {
			return fields
		}
		if err != nil {
			t.Fatal(err)
		}
		fields = append(fields, field)
	}
}

// ReadMessage reads initial HEADERS, DATA and optional trailers through FIN.
func ReadMessage(t *testing.T, reader io.Reader) ([]qpack.HeaderField, []byte, []qpack.HeaderField) {
	t.Helper()
	fields := ReadHeaders(t, reader)
	var body []byte
	var trailers []qpack.HeaderField
	for {
		frame, err := ReadFrame(reader)
		if errors.Is(err, io.EOF) {
			return fields, body, trailers
		}
		if err != nil {
			t.Fatal(err)
		}
		switch frame.Kind {
		case 0:
			body = append(body, frame.Payload...)
		case 1:
			trailers = decodeHeaders(t, frame.Payload)
		default:
			t.Fatalf("message frame type = %d; want DATA or trailers", frame.Kind)
		}
	}
}
