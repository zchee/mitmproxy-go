// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http1

import (
	"errors"
	"io"
	"strconv"

	"github.com/zchee/mitmproxy-go/httpmsg"
)

// BodyWriter streams a framed body to a transport without buffering the body.
// Use Close to terminate chunked encoding or check the declared length. Close
// never closes or flushes the underlying transport. It is not concurrency-safe.
// Construct it with NewBodyWriter rather than using its zero value.
type BodyWriter struct {
	writer    io.Writer
	size      BodySize
	remaining int64
	closed    bool
	err       error
}

// NewBodyWriter returns a writer for size. It rejects a nil transport, unknown
// modes and negative lengths without writing bytes. Only BodyLength uses Length.
func NewBodyWriter(writer io.Writer, size BodySize) (*BodyWriter, error) {
	if writer == nil {
		return nil, errors.New("nil HTTP body writer")
	}
	if err := validateBodySize(size); err != nil {
		return nil, err
	}
	return &BodyWriter{writer: writer, size: size, remaining: size.Length}, nil
}

// Write writes one body fragment. Empty fragments are ignored. Chunked fragments
// each produce one chunk with a lowercase hexadecimal length. A fragment longer
// than the remaining Content-Length is rejected without writing any of it.
// Short transport writes return io.ErrShortWrite. Errors are terminal.
func (b *BodyWriter) Write(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	if b.size.Mode == BodyNone || b.size.Mode == BodyLength && int64(len(p)) > b.remaining {
		b.err = errors.New("Too much data for declared Content-Length") //nolint:staticcheck // Preserve h11's user-facing diagnostic.
		return 0, b.err
	}
	if b.size.Mode == BodyChunked {
		if _, err := b.write([]byte(strconv.FormatInt(int64(len(p)), 16) + "\r\n")); err != nil {
			return 0, err
		}
	}
	n, err := b.write(p)
	if b.size.Mode == BodyLength {
		b.remaining -= int64(n)
	}
	if err == nil && b.size.Mode == BodyChunked {
		_, err = b.write([]byte("\r\n"))
	}
	return n, err
}

func (b *BodyWriter) write(p []byte) (int, error) {
	n, err := b.writer.Write(p)
	if n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	b.err = err
	return n, err
}

// Close completes a message, writing the final chunk and trailers for chunked
// encoding. Nonempty trailers with another mode and incomplete Content-Length
// bodies return errors. Repeated calls return the original result without
// emitting anything. Trailer spelling follows Headers.Bytes, as in upstream.
func (b *BodyWriter) Close(trailers httpmsg.Headers) error {
	if b.closed || b.err != nil {
		return b.err
	}
	b.closed = true
	if len(trailers) != 0 && b.size.Mode != BodyChunked {
		b.err = errors.New("Sending HTTP/1.1 trailer headers requires transfer-encoding: chunked") //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
		return b.err
	}
	if b.size.Mode == BodyLength && b.remaining != 0 {
		b.err = errors.New("Too little data for declared Content-Length") //nolint:staticcheck // Preserve h11's user-facing diagnostic.
		return b.err
	}
	if b.size.Mode == BodyChunked {
		if _, err := b.write([]byte("0\r\n")); err != nil {
			return err
		}
		for _, field := range trailers {
			if _, err := b.write(appendField(nil, field)); err != nil {
				return err
			}
		}
		_, b.err = b.write([]byte("\r\n"))
	}
	return b.err
}
