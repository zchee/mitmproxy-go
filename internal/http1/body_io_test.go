// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http1

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

type limitedWriter struct {
	bytes.Buffer
	remaining int
	failure   error
	closed    bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		n, _ := w.Buffer.Write(p[:w.remaining])
		w.remaining = 0
		return n, w.failure
	}
	w.remaining -= len(p)
	return w.Buffer.Write(p)
}

func (w *limitedWriter) Close() error { w.closed = true; return nil }

func TestBodyWriterTransportErrors(t *testing.T) {
	failure := errors.New("transport failed")
	tests := map[string]struct {
		limit   int
		cause   error
		written int
	}{
		"header error":      {limit: 0, cause: failure},
		"short header":      {limit: 2},
		"payload error":     {limit: 4, cause: failure, written: 1},
		"short payload":     {limit: 5, written: 2},
		"footer error":      {limit: 6, cause: failure, written: 3},
		"short footer":      {limit: 7, written: 3},
		"final chunk error": {limit: 8, cause: failure, written: 3},
		"short final chunk": {limit: 10, written: 3},
		"trailer error":     {limit: 11, cause: failure, written: 3},
		"short trailer":     {limit: 12, written: 3},
		"terminator error":  {limit: 17, cause: failure, written: 3},
		"short terminator":  {limit: 18, written: 3},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			transport := &limitedWriter{remaining: tt.limit, failure: tt.cause}
			writer, err := NewBodyWriter(transport, BodySize{Mode: BodyChunked})
			if err != nil {
				t.Fatal(err)
			}
			n, err := writer.Write([]byte("abc"))
			if n != tt.written {
				t.Fatalf("payload count=%d, want %d", n, tt.written)
			}
			if err == nil {
				err = writer.Close(fields("X", "y"))
			}
			want := tt.cause
			if want == nil {
				want = io.ErrShortWrite
			}
			if !errors.Is(err, want) {
				t.Fatalf("error=%v, want %v", err, want)
			}
			if transport.String() != "3\r\nabc\r\n0\r\nX: y\r\n\r\n"[:tt.limit] {
				t.Fatalf("wire=%q", transport.String())
			}
			if next := writer.Close(nil); next != err {
				t.Fatalf("terminal error=%v, want %v", next, err)
			}
			if transport.closed {
				t.Fatal("body closed underlying transport")
			}
		})
	}
}

func TestBodyReaderTransportErrors(t *testing.T) {
	failure := errors.New("transport failed")
	tests := map[string]struct {
		mode   BodyMode
		prefix string
	}{
		"length":         {mode: BodyLength},
		"until close":    {mode: BodyUntilClose},
		"chunk header":   {mode: BodyChunked},
		"chunk payload":  {mode: BodyChunked, prefix: "1\r\n"},
		"chunk footer":   {mode: BodyChunked, prefix: "1\r\nx"},
		"chunk trailers": {mode: BodyChunked, prefix: "0\r\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			transport := io.MultiReader(strings.NewReader(tt.prefix), iotest.ErrReader(failure))
			body, err := NewBodyReader(bufio.NewReader(transport), BodySize{Mode: tt.mode, Length: 1})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(io.Discard, body); !errors.Is(err, failure) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestChunkedConstructorIgnoresLength(t *testing.T) {
	body, err := NewBodyReader(bufio.NewReader(strings.NewReader("0\r\n\r\n")), BodySize{Mode: BodyChunked, Length: 123})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := body.Read(nil); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(body); err != nil || len(got) != 0 {
		t.Fatalf("body=%q error=%v", got, err)
	}
}
