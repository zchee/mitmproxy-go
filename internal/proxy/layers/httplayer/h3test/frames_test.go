// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go/quicvarint"
)

func TestFrames(t *testing.T) {
	tests := map[string]struct {
		kind    uint64
		payload []byte
	}{
		"success: data":             {payload: []byte("payload")},
		"success: empty settings":   {kind: 4},
		"success: extension varint": {kind: 0xface, payload: []byte("ignored")},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var wire bytes.Buffer
			WriteFrame(t, &wire, test.kind, test.payload)
			frame, err := ReadFrame(&wire)
			if err != nil {
				t.Fatal(err)
			}
			if frame.Kind != test.kind || !bytes.Equal(frame.Payload, test.payload) {
				t.Fatalf("frame = %+v; want kind=%d payload=%q", frame, test.kind, test.payload)
			}
			if _, err := ReadFrame(&wire); !errors.Is(err, io.EOF) {
				t.Fatalf("between-frame EOF = %v", err)
			}
		})
	}
}

func TestMessage(t *testing.T) {
	fields := []qpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "x-duplicate", Value: "first"}, {Name: "x-duplicate", Value: "second"}}
	trailers := []qpack.HeaderField{{Name: "x-trailer", Value: "done"}}
	var wire bytes.Buffer
	WriteHeaders(t, &wire, fields)
	WriteFrame(t, &wire, 0, []byte("first"))
	WriteFrame(t, &wire, 0, []byte("second"))
	WriteHeaders(t, &wire, trailers)
	actualFields, body, actualTrailers := ReadMessage(t, &wire)
	if diff := gocmp.Diff(fields, actualFields); diff != "" {
		t.Fatal(diff)
	}
	if diff := gocmp.Diff(trailers, actualTrailers); diff != "" {
		t.Fatal(diff)
	}
	if string(body) != "firstsecond" {
		t.Fatalf("body = %q", body)
	}
}

func TestFrameErrors(t *testing.T) {
	oversized := quicvarint.Append([]byte{0}, 1<<20+1)
	tests := map[string]struct {
		wire []byte
		want error
	}{
		"error: missing frame length": {wire: []byte{0}, want: io.ErrUnexpectedEOF},
		"error: truncated payload":    {wire: []byte{0, 3, 'x'}, want: io.ErrUnexpectedEOF},
		"error: oversized payload":    {wire: oversized},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadFrame(bytes.NewReader(test.wire)); err == nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("frame error = %v; want %v", err, test.want)
			}
		})
	}
}
