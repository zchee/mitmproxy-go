// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http1

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

var (
	chunkHeader   = regexp.MustCompile(`^([0-9A-Fa-f]{1,20})(;[^\n]*)?[ \t]*\r\n$`)
	trailerName   = regexp.MustCompile("^[-!#$%&'*+.^_`|~0-9a-zA-Z]+$")
	trailerLength = regexp.MustCompile(`^[0-9]{1,20}$`)
)

// BodyReader streams one framed body without consuming the following message.
// It retains only framing state and bounded trailers, never the entire body.
// A reader belongs to one goroutine; separate readers may be used concurrently.
// Construct it with NewBodyReader rather than using its zero value.
type BodyReader struct {
	reader    *bufio.Reader
	size      BodySize
	remaining int64
	footer    bool
	trailers  httpmsg.Headers
	err       error
}

// NewBodyReader selects a streaming reader for size. Unknown modes, negative
// lengths and a nil reader return an error without reading any bytes. A length
// is used only for BodyLength; BodyNone consumes no bytes, even if bytes follow.
func NewBodyReader(reader *bufio.Reader, size BodySize) (*BodyReader, error) {
	if reader == nil {
		return nil, errors.New("nil HTTP body reader")
	}
	if err := validateBodySize(size); err != nil {
		return nil, err
	}
	body := &BodyReader{reader: reader, size: size}
	if size.Mode == BodyLength {
		body.remaining = size.Length
	}
	return body, nil
}

func validateBodySize(size BodySize) error {
	if size.Mode > BodyUntilClose {
		return fmt.Errorf("unknown HTTP body mode: %d", size.Mode)
	}
	if size.Length < 0 {
		return errors.New("negative HTTP body length")
	}
	return nil
}

// Read returns decoded body bytes. Premature EOF wraps io.ErrUnexpectedEOF with
// upstream's incomplete-body detail. Bad chunk syntax and trailers return an
// error; chunk sizes must fit int64. Each resource cap has its own sentinel.
// An error is terminal and returned again on subsequent nonempty reads.
func (b *BodyReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.err != nil {
		return 0, b.err
	}
	var n int
	var err error
	switch b.size.Mode {
	case BodyNone:
		err = io.EOF
	case BodyLength:
		if b.remaining == 0 {
			err = io.EOF
			break
		}
		n, err = b.reader.Read(p[:min(int64(len(p)), b.remaining)])
		b.remaining -= int64(n)
		if errors.Is(err, io.EOF) {
			if b.remaining == 0 {
				err = nil
			} else {
				err = fmt.Errorf("peer closed connection without sending complete message body (received %d bytes, expected %d): %w", b.size.Length-b.remaining, b.size.Length, io.ErrUnexpectedEOF)
			}
		}
	case BodyChunked:
		n, err = b.readChunked(p)
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) && b.trailers == nil {
			err = fmt.Errorf("peer closed connection without sending complete message body (incomplete chunked read): %w", io.ErrUnexpectedEOF)
		}
	case BodyUntilClose:
		n, err = b.reader.Read(p)
	}
	b.err = err
	return n, err
}

// Trailers returns an owned copy of trailers after a chunked body reaches EOF.
// It returns nil before completion, for an empty trailer block, or for a body
// that is not chunked. Reading the complete body is required to validate them.
func (b *BodyReader) Trailers() httpmsg.Headers {
	if len(b.trailers) == 0 {
		return nil
	}
	return b.trailers.Clone()
}

func (b *BodyReader) readChunked(p []byte) (int, error) {
	if b.remaining == 0 {
		if b.footer {
			var footer [2]byte
			n, err := io.ReadFull(b.reader, footer[:])
			if !bytes.Equal(footer[:n], []byte("\r\n")[:n]) {
				return 0, fmt.Errorf("malformed chunk footer: bytearray(%s) (expected b'\\r\\n')", pyrepr.Bytes(footer[:n]))
			}
			if err != nil {
				return 0, err
			}
		}
		line, err := b.readChunkLine()
		if err != nil {
			return 0, err
		}
		parts := chunkHeader.FindSubmatch(line)
		if parts == nil {
			return 0, fmt.Errorf("illegal chunk header: bytearray(%s)", pyrepr.Bytes(line))
		}
		b.remaining, err = strconv.ParseInt(string(parts[1]), 16, 64)
		if err != nil {
			return 0, errors.New("chunk size exceeds int64")
		}
		if b.remaining == 0 {
			b.trailers, err = readTrailers(b.reader)
			if err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
		b.footer = true
	}
	n, err := b.reader.Read(p[:min(int64(len(p)), b.remaining)])
	b.remaining -= int64(n)
	return n, err
}

func (b *BodyReader) readChunkLine() ([]byte, error) {
	var line []byte
	for {
		part, err := b.reader.ReadSlice('\n')
		if len(part) > MaxChunkLineBytes-len(line) {
			return nil, fmt.Errorf("%w: maximum %d", ErrChunkLineTooLong, MaxChunkLineBytes)
		}
		line = append(line, part...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if bytes.HasSuffix(line, []byte("\r\n")) {
			return line, nil
		}
	}
}

func readTrailers(reader *bufio.Reader) (httpmsg.Headers, error) {
	var lines [][]byte
	total := 0
	for {
		line, err := readLine(reader, MaxLineBytes, MaxHeadBytes-total, ErrLineTooLong)
		if err != nil {
			return nil, err
		}
		total += len(line)
		line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte{'\n'}), []byte{'\r'})
		if len(line) == 0 {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(lines) == 0 {
				return nil, errors.New("continuation line at start of headers")
			}
			last := len(lines) - 1
			lines[last] = append(lines[last], ' ')
			lines[last] = append(lines[last], bytes.TrimLeft(line, " \t")...)
		} else {
			if len(lines) == MaxHeaderFields {
				return nil, fmt.Errorf("%w: maximum %d", ErrTooManyHeaders, MaxHeaderFields)
			}
			lines = append(lines, line)
		}
	}
	// h11 validates trailer framing fields differently from mitmproxy's heads:
	// equal comma-separated lengths coalesce, and only chunked TE is accepted.
	headers := make(httpmsg.Headers, 0, len(lines))
	var contentLength []byte
	sawEncoding := false
	for _, line := range lines {
		name, value, ok := bytes.Cut(line, []byte{':'})
		value = bytes.Trim(value, " \t")
		if !ok || !trailerName.Match(name) || bytes.ContainsAny(value, "\x00\r\n\v\f") {
			return nil, fmt.Errorf("illegal header line: %s", pyrepr.Bytes(line))
		}
		switch strings.ToLower(string(name)) {
		case "content-length":
			var length []byte
			first := true
			for part := range bytes.SplitSeq(value, []byte{','}) {
				part = bytes.Trim(part, asciiWhitespace)
				if !first && !bytes.Equal(length, part) {
					return nil, errors.New("conflicting Content-Length headers")
				}
				length, first = part, false
			}
			if !trailerLength.Match(length) {
				return nil, errors.New("bad Content-Length")
			}
			if contentLength != nil {
				if !bytes.Equal(contentLength, length) {
					return nil, errors.New("conflicting Content-Length headers")
				}
				continue
			}
			contentLength, value = length, length
		case "transfer-encoding":
			if sawEncoding {
				return nil, errors.New("multiple Transfer-Encoding headers")
			}
			value = bytes.ToLower(value)
			if !bytes.Equal(value, []byte("chunked")) {
				return nil, errors.New("Only Transfer-Encoding: chunked is supported") //nolint:staticcheck // Preserve h11's user-facing diagnostic.
			}
			sawEncoding = true
		}
		owned := make([]byte, len(value))
		copy(owned, value)
		headers = append(headers, httpmsg.Field{Name: bytes.Clone(name), Value: owned})
	}
	return headers, nil
}
