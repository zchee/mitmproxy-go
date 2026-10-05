// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http1

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"testing/iotest"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestBodyReader(t *testing.T) {
	tests := map[string]struct {
		size                  BodySize
		wire, want, remaining string
		trailers              httpmsg.Headers
	}{
		"none":                          {size: BodySize{}, wire: "NEXT", remaining: "NEXT"},
		"zero length":                   {size: BodySize{Mode: BodyLength}, wire: "NEXT", remaining: "NEXT"},
		"length":                        {size: BodySize{Mode: BodyLength, Length: 4}, wire: "bodyNEXT", want: "body", remaining: "NEXT"},
		"until close":                   {size: BodySize{Mode: BodyUntilClose}, wire: "body", want: "body"},
		"chunked":                       {size: BodySize{Mode: BodyChunked}, wire: "2\r\nbo\r\n2\r\ndy\r\n0\r\n\r\nNEXT", want: "body", remaining: "NEXT"},
		"extensions":                    {size: BodySize{Mode: BodyChunked}, wire: "A;ignored=anything\r\n0123456789\r\n0;end\r\n\r\nNEXT", want: "0123456789", remaining: "NEXT"},
		"trailing chunk whitespace":     {size: BodySize{Mode: BodyChunked}, wire: "1 \t\r\nx\r\n0\r\n\r\n", want: "x"},
		"trailers":                      {size: BodySize{Mode: BodyChunked}, wire: "0\r\nSet-Cookie: a=b; \r\n\t Secure\r\nSet-Cookie: c=d\r\nEmpty:\r\n\r\nNEXT", remaining: "NEXT", trailers: fields("Set-Cookie", "a=b;  Secure", "Set-Cookie", "c=d", "Empty", "")},
		"LF trailers":                   {size: BodySize{Mode: BodyChunked}, wire: "0\r\nX: y\n\nNEXT", remaining: "NEXT", trailers: fields("X", "y")},
		"trailer framing normalization": {size: BodySize{Mode: BodyChunked}, wire: "0\r\nContent-Length: 01, 01\r\nContent-Length: 01\r\nTransfer-Encoding: CHUNKED\r\n\r\n", trailers: fields("Content-Length", "01", "Transfer-Encoding", "chunked")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			reader := bufio.NewReader(iotest.OneByteReader(strings.NewReader(tt.wire)))
			body, err := NewBodyReader(reader, tt.size)
			if err != nil {
				t.Fatal(err)
			}
			if got := body.Trailers(); got != nil {
				t.Fatalf("early trailers=%v", got)
			}
			got, err := io.ReadAll(body)
			if err != nil || string(got) != tt.want {
				t.Fatalf("body=%q error=%v, want %q", got, err, tt.want)
			}
			if diff := gocmp.Diff(tt.trailers, body.Trailers()); diff != "" {
				t.Fatalf("trailers (-want +got):\n%s", diff)
			}
			if trailers := body.Trailers(); len(trailers) != 0 {
				clear(trailers[0].Name)
				if diff := gocmp.Diff(tt.trailers, body.Trailers()); diff != "" {
					t.Fatalf("trailers alias reader: %s", diff)
				}
			}
			left, err := io.ReadAll(reader)
			if err != nil || string(left) != tt.remaining {
				t.Fatalf("remaining=%q error=%v, want %q", left, err, tt.remaining)
			}
		})
	}
}

func TestBodyErrors(t *testing.T) {
	tests := map[string]struct {
		size          BodySize
		wire, message string
		cause         error
	}{
		"short length":               {size: BodySize{Mode: BodyLength, Length: 5}, wire: "abc", cause: io.ErrUnexpectedEOF, message: "peer closed connection without sending complete message body (received 3 bytes, expected 5)"},
		"enormous length":            {size: BodySize{Mode: BodyLength, Length: 1<<63 - 1}, cause: io.ErrUnexpectedEOF},
		"chunk eof":                  {size: BodySize{Mode: BodyChunked}, wire: "3\r\nab", cause: io.ErrUnexpectedEOF, message: "peer closed connection without sending complete message body (incomplete chunked read)"},
		"bare LF chunk":              {size: BodySize{Mode: BodyChunked}, wire: "1\nx", cause: io.ErrUnexpectedEOF},
		"invalid size":               {size: BodySize{Mode: BodyChunked}, wire: "g\r\n", message: "illegal chunk header: bytearray(b'g\\r\\n')"},
		"negative size":              {size: BodySize{Mode: BodyChunked}, wire: "-1\r\n", message: "illegal chunk header:"},
		"size with bare CR":          {size: BodySize{Mode: BodyChunked}, wire: "5\r\r\nhello\r\n0\r\n\r\n", message: "illegal chunk header: bytearray(b'5\\r\\r\\n')"},
		"size with vertical tab":     {size: BodySize{Mode: BodyChunked}, wire: "5\v\r\nhello\r\n0\r\n\r\n", message: "illegal chunk header:"},
		"size with form feed":        {size: BodySize{Mode: BodyChunked}, wire: "5\f\r\nhello\r\n0\r\n\r\n", message: "illegal chunk header:"},
		"twenty one digits":          {size: BodySize{Mode: BodyChunked}, wire: strings.Repeat("0", 21) + "\r\n", message: "illegal chunk header:"},
		"range overflow":             {size: BodySize{Mode: BodyChunked}, wire: "8000000000000000\r\n", message: "chunk size exceeds int64"},
		"enormous chunk":             {size: BodySize{Mode: BodyChunked}, wire: "7fffffffffffffff\r\n", cause: io.ErrUnexpectedEOF},
		"chunk cap":                  {size: BodySize{Mode: BodyChunked}, wire: "1;" + strings.Repeat("x", MaxChunkLineBytes), cause: ErrChunkLineTooLong},
		"bad footer":                 {size: BodySize{Mode: BodyChunked}, wire: "1\r\nxab", message: "malformed chunk footer:"},
		"trailer name":               {size: BodySize{Mode: BodyChunked}, wire: "0\r\nBad Name: x\r\n\r\n", message: "illegal header line:"},
		"orphan fold":                {size: BodySize{Mode: BodyChunked}, wire: "0\r\n folded\r\n\r\n", message: "continuation line at start of headers"},
		"trailer NUL":                {size: BodySize{Mode: BodyChunked}, wire: "0\r\nX: a\x00b\r\n\r\n", message: "illegal header line:"},
		"trailer whitespace":         {size: BodySize{Mode: BodyChunked}, wire: "0\r\nX: a\vb\r\n\r\n", message: "illegal header line:"},
		"trailer line cap":           {size: BodySize{Mode: BodyChunked}, wire: "0\r\nX: " + strings.Repeat("x", MaxLineBytes) + "\r\n\r\n", cause: ErrLineTooLong},
		"trailer head cap":           {size: BodySize{Mode: BodyChunked}, wire: "0\r\n" + strings.Repeat("X: "+strings.Repeat("x", 1000)+"\r\n", 1100) + "\r\n", cause: ErrHeadTooLarge},
		"trailer field cap":          {size: BodySize{Mode: BodyChunked}, wire: "0\r\n" + strings.Repeat("X: y\r\n", MaxHeaderFields+1) + "\r\n", cause: ErrTooManyHeaders},
		"conflicting trailer length": {size: BodySize{Mode: BodyChunked}, wire: "0\r\nContent-Length: 1, 2\r\n\r\n", message: "conflicting Content-Length headers"},
		"invalid trailer length":     {size: BodySize{Mode: BodyChunked}, wire: "0\r\nContent-Length: no\r\n\r\n", message: "bad Content-Length"},
		"invalid trailer encoding":   {size: BodySize{Mode: BodyChunked}, wire: "0\r\nTransfer-Encoding: gzip\r\n\r\n", message: "Only Transfer-Encoding: chunked is supported"},
		"duplicate trailer encoding": {size: BodySize{Mode: BodyChunked}, wire: "0\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", message: "multiple Transfer-Encoding headers"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			body, err := NewBodyReader(bufio.NewReader(strings.NewReader(tt.wire)), tt.size)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, body)
			if err == nil || (tt.cause != nil && !errors.Is(err, tt.cause)) || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("error=%v, want cause=%v message=%q", err, tt.cause, tt.message)
			}
			if _, next := body.Read(make([]byte, 1)); next != err {
				t.Fatalf("terminal error changed: %v -> %v", err, next)
			}
		})
	}
}

func TestChunkTruncation(t *testing.T) {
	wire := "2;extension\r\nab\r\n1\r\nc\r\n0\r\nX: y\r\n\r\n"
	for end := range len(wire) {
		body, err := NewBodyReader(bufio.NewReader(iotest.OneByteReader(strings.NewReader(wire[:end]))), BodySize{Mode: BodyChunked})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.Copy(io.Discard, body); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("prefix %d/%d: %v", end, len(wire), err)
		}
	}
}

func TestBodySizeValidation(t *testing.T) {
	tests := map[string]struct{ size BodySize }{
		"unknown mode":    {BodySize{Mode: 255}},
		"negative length": {BodySize{Mode: BodyLength, Length: -1}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewBodyReader(bufio.NewReader(strings.NewReader("")), tt.size); err == nil {
				t.Fatal("reader accepted invalid framing")
			}
			if _, err := NewBodyWriter(io.Discard, tt.size); err == nil {
				t.Fatal("writer accepted invalid framing")
			}
		})
	}
}

func TestBodyWriter(t *testing.T) {
	tests := map[string]struct {
		size          BodySize
		chunks        []string
		trailers      httpmsg.Headers
		want, message string
	}{
		"length":               {size: BodySize{Mode: BodyLength, Length: 6}, chunks: []string{"foo", "bar"}, want: "foobar"},
		"until close":          {size: BodySize{Mode: BodyUntilClose}, chunks: []string{"foo", "bar"}, want: "foobar"},
		"chunked":              {size: BodySize{Mode: BodyChunked}, chunks: []string{"foo", "bar"}, want: "3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n"},
		"empty chunks":         {size: BodySize{Mode: BodyChunked}, chunks: []string{"", "foo", "", "bar", ""}, want: "3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n"},
		"trailers":             {size: BodySize{Mode: BodyChunked}, chunks: []string{"foo"}, trailers: fields("foo", "bar"), want: "3\r\nfoo\r\n0\r\nfoo: bar\r\n\r\n"},
		"non chunked trailers": {size: BodySize{Mode: BodyUntilClose}, trailers: fields("foo", "bar"), message: "Sending HTTP/1.1 trailer headers requires transfer-encoding: chunked"},
		"no body":              {size: BodySize{}},
		"too long":             {size: BodySize{Mode: BodyLength, Length: 2}, chunks: []string{"foo"}, message: "Too much data for declared Content-Length"},
		"too short":            {size: BodySize{Mode: BodyLength, Length: 4}, chunks: []string{"foo"}, want: "foo", message: "Too little data for declared Content-Length"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var buffer bytes.Buffer
			writer, err := NewBodyWriter(&buffer, tt.size)
			if err != nil {
				t.Fatal(err)
			}
			for _, chunk := range tt.chunks {
				var n int
				n, err = writer.Write([]byte(chunk))
				if err != nil {
					break
				}
				if n != len(chunk) {
					t.Fatalf("short write %d/%d", n, len(chunk))
				}
			}
			if err == nil {
				err = writer.Close(tt.trailers)
			}
			if (tt.message == "" && err != nil) || (tt.message != "" && (err == nil || err.Error() != tt.message)) {
				t.Fatalf("error=%v, want %q", err, tt.message)
			}
			if buffer.String() != tt.want {
				t.Fatalf("wire=%q, want %q", buffer.String(), tt.want)
			}
			before := buffer.Len()
			if next := writer.Close(tt.trailers); next != err {
				t.Fatalf("repeated Close=%v, want %v", next, err)
			}
			if buffer.Len() != before {
				t.Fatal("repeated Close emitted bytes")
			}
			if _, err := writer.Write([]byte("more")); err == nil {
				t.Fatal("write after terminal state accepted")
			}
		})
	}
}

func TestAssembleWholeMessages(t *testing.T) {
	// Missing-content errors from upstream's whole-message wrappers do not apply:
	// the streaming API receives body bytes through Write, not RawContent.
	tests := map[string]struct{ response, chunked bool }{
		"request": {}, "response": {response: true}, "chunked response": {response: true, chunked: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			req, resp := testflow.TReq(), testflow.TResp()
			var buffer bytes.Buffer
			content := req.RawContent
			var trailers httpmsg.Headers
			var response *httpmsg.Response
			if tt.response {
				response = resp
				content = resp.RawContent
				if tt.chunked {
					resp.Headers.Set("transfer-encoding", "chunked")
					trailers = fields("foo", "bar")
				}
				buffer.Write(AssembleResponseHead(resp, nil, false, nil))
			} else {
				buffer.Write(AssembleRequestHead(req, nil, false, nil))
			}
			size, err := ExpectedBodySize(req, response)
			if err != nil {
				t.Fatal(err)
			}
			writer, err := NewBodyWriter(&buffer, size)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = writer.Write(content); err != nil {
				t.Fatal(err)
			}
			if err = writer.Close(trailers); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(&buffer)
			if tt.response {
				_, err = ReadResponseHead(reader)
			} else {
				_, err = ReadRequestHead(reader)
			}
			if err != nil {
				t.Fatal(err)
			}
			body, err := NewBodyReader(reader, size)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(body)
			if err != nil || !bytes.Equal(got, content) {
				t.Fatalf("content=%q error=%v", got, err)
			}
			if diff := gocmp.Diff(trailers, body.Trailers()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestConcurrentBodyReaders(t *testing.T) {
	var group sync.WaitGroup
	for range 32 {
		group.Go(func() {
			body, err := NewBodyReader(bufio.NewReader(strings.NewReader("3\r\nabc\r\n0\r\nX: y\r\n\r\n")), BodySize{Mode: BodyChunked})
			if err != nil {
				t.Error(err)
				return
			}
			got, err := io.ReadAll(body)
			if err != nil || string(got) != "abc" || body.Trailers().Get("X") != "y" {
				t.Errorf("body=%q error=%v trailers=%v", got, err, body.Trailers())
			}
		})
	}
	group.Wait()
}
