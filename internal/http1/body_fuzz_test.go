// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http1

import (
	"bufio"
	"bytes"
	"io"
	"testing"
	"testing/iotest"

	gocmp "github.com/google/go-cmp/cmp"
)

func FuzzChunked(f *testing.F) {
	for _, seed := range []string{
		"0\r\n\r\n", "3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n",
		"3;foo=bar\r\nabc\r\n0\r\nX: y\r\n\r\nNEXT",
		"0\r\nSet-Cookie: a=b;\r\n\tSecure\r\n\r\n",
		"0\r\nContent-Length: 01, 01\r\n\r\n", "1\r\nxab", "-1\r\n",
		"ffffffffffffffffffff\r\n", "1;long extension", "0\r\nX:\x00\r\n\r\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > MaxHeadBytes {
			return
		}
		reader, err := NewBodyReader(bufio.NewReader(bytes.NewReader(wire)), BodySize{Mode: BodyChunked})
		if err != nil {
			t.Fatal(err)
		}
		body, parseErr := io.ReadAll(reader)
		fragmented, err := NewBodyReader(bufio.NewReader(iotest.OneByteReader(bytes.NewReader(wire))), BodySize{Mode: BodyChunked})
		if err != nil {
			t.Fatal(err)
		}
		other, otherErr := io.ReadAll(fragmented)
		if (parseErr == nil) != (otherErr == nil) {
			t.Fatalf("fragmentation changed acceptance: %v versus %v", parseErr, otherErr)
		}
		if parseErr != nil {
			return
		}
		if !bytes.Equal(body, other) || !gocmp.Equal(reader.Trailers(), fragmented.Trailers()) {
			t.Fatal("fragmentation changed decoded message")
		}
		var buffer bytes.Buffer
		writer, err := NewBodyWriter(&buffer, BodySize{Mode: BodyChunked})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(reader.Trailers()); err != nil {
			t.Fatal(err)
		}
		roundtrip, err := NewBodyReader(bufio.NewReader(&buffer), BodySize{Mode: BodyChunked})
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(roundtrip)
		if err != nil || !bytes.Equal(got, body) || !gocmp.Equal(roundtrip.Trailers(), reader.Trailers()) {
			t.Fatalf("round trip changed decoded body or trailers: %v", err)
		}
	})
}
