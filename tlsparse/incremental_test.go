// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsparse

import (
	"bytes"
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func incrementalHello(fragment bool) []byte {
	body := make([]byte, 4092)
	copy(body, []byte{3, 3})
	copy(body[35:], []byte{0, 2, 0, 0x2f, 1, 0, 0x0f, 0xd1, 0, 21, 0x0f, 0xcd})
	message := append([]byte{1, 0, 0x0f, 0xfc}, body...)
	if !fragment {
		return append([]byte{0x16, 3, 3, 0x10, 0}, message...)
	}
	wire := make([]byte, 0, len(message)*6)
	for _, b := range message {
		wire = append(wire, 0x16, 3, 3, 0, 1, b)
	}
	return wire
}

func TestClientHelloParser(t *testing.T) {
	tests := map[string]struct {
		data    []byte
		err     error
		records int
	}{
		"success: whole record":                   {data: incrementalHello(false), records: 1},
		"success: one byte per record":            {data: incrementalHello(true), records: 4096},
		"error: oversize before record completes": {data: []byte{0x16, 3, 3, 255, 255, 1, 0, 255, 253}, err: ErrTooLarge, records: 1},
		"error: oversize across records":          {data: []byte{0x16, 3, 3, 0, 2, 1, 0, 0x16, 3, 3, 255, 255, 255, 253}, err: ErrTooLarge, records: 2},
		"error: empty record":                     {data: []byte{0x16, 3, 3, 0, 0}, err: ErrMalformed},
		"error: invalid record":                   {data: []byte{0x17, 3, 3, 0, 1}, err: ErrMalformed},
		"error: invalid hello":                    {data: []byte{0x16, 3, 3, 0, 4, 1, 0, 0, 0}, err: ErrMalformed, records: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var parser ClientHelloParser
			var got *ClientHello
			var err error
			for end := 0; end <= len(tt.data); end++ {
				got, err = parser.Parse(tt.data[:end])
				if end < len(tt.data) && (got != nil || err != nil) {
					t.Fatalf("premature result at %d bytes: %v, %v", end, got, err)
				}
			}
			if !errors.Is(err, tt.err) || parser.records != tt.records {
				t.Fatalf("Parse: %v, %v; record headers examined %d, want %d; expected error %v", got, err, parser.records, tt.records, tt.err)
			}
			want, wantErr := ParseClientHello(tt.data)
			if (got == nil) != (want == nil) || (err == nil) != (wantErr == nil) {
				t.Fatalf("incremental result %v, %v differs from stateless %v, %v", got, err, want, wantErr)
			}
			if got != nil && want != nil {
				if diff := gocmp.Diff(want.RawBytes(false), got.RawBytes(false)); diff != "" {
					t.Fatalf("hello (-want +got):\n%s", diff)
				}
			}
			previousRecords := parser.records
			if again, againErr := parser.Parse(append(bytes.Clone(tt.data), 0)); again != got || !errors.Is(againErr, err) || parser.records != previousRecords {
				t.Fatalf("completed parser rescanned input: %v, %v, %d records", again, againErr, parser.records)
			}
		})
	}
}

func FuzzClientHelloParser(f *testing.F) {
	f.Add(incrementalHello(false), uint16(1))
	f.Add(incrementalHello(true), uint16(1))
	f.Add([]byte{0x16, 3, 3, 255, 255, 1, 0, 255, 253}, uint16(2))
	f.Fuzz(func(t *testing.T, data []byte, window uint16) {
		if len(data) > 128<<10 {
			return
		}
		var parser ClientHelloParser
		step := 1 + int(window)%256
		var got *ClientHello
		var err error
		for end := 0; end < len(data); end += step {
			got, err = parser.Parse(data[:min(end+step, len(data))])
			if got != nil || err != nil {
				break
			}
		}
		want, wantErr := ParseClientHello(data)
		if (got == nil) != (want == nil) || (err == nil) != (wantErr == nil) || errors.Is(err, ErrTooLarge) != errors.Is(wantErr, ErrTooLarge) {
			t.Fatalf("incremental %v, %v; stateless %v, %v", got, err, want, wantErr)
		}
		if got != nil && !bytes.Equal(got.RawBytes(false), want.RawBytes(false)) {
			t.Fatal("incremental and stateless hello bytes differ")
		}
	})
}
