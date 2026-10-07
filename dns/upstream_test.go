// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"bytes"
	"encoding/hex"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestNameCompression(t *testing.T) {
	tests := map[string]struct {
		data   []byte
		offset int
		name   string
		length int
	}{
		"offset":         {data: []byte("\xff\x03www\x07example\x03org\x00"), offset: 1, name: "www.example.org", length: 17},
		"suffix pointer": {data: []byte("\xff\xff\xff\x07example\x03org\x00\xff\xff\xff\x03www\xc0\x03"), offset: 19, name: "www.example.org", length: 6},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, end, err := unpackName(tt.data, tt.offset, true)
			if err != nil || got != tt.name || end-tt.offset != tt.length {
				t.Fatalf("unpackName = %q, consumed %d, %v; want %q, %d", got, end-tt.offset, err, tt.name, tt.length)
			}
		})
	}
	if _, _, err := unpackName([]byte("\x03www\xc0\x00"), 0, true); err == nil {
		t.Fatal("compression loop accepted")
	}
}

func TestHTTPSAllParameters(t *testing.T) {
	// Exact test_https_records.py::test_pack vector, including both address hints.
	wire, err := hex.DecodeString("0001076578616d706c6503636f6d00000000040004000600010006026832026833000200000003000201bb00040010b9c76c99b9c76d99b9c76e99b9c76f990005000974657374627974657300060040260650c0800000000000000000000153260650c0800100000000000000000153260650c0800200000000000000000153260650c0800300000000000000000153")
	if err != nil {
		t.Fatal(err)
	}
	record, err := UnpackHTTPS(wire)
	if err != nil {
		t.Fatal(err)
	}
	if record.Priority != 1 || record.TargetName != "example.com" || len(record.Params) != 7 {
		t.Fatalf("unexpected HTTPS record: %+v", record)
	}
	packed, err := PackHTTPS(record)
	if err != nil || !bytes.Equal(packed, wire) {
		t.Fatalf("HTTPS wire round trip = %x, %v; want %x", packed, err, wire)
	}
	wireBefore := bytes.Clone(wire)
	record.Params[0].Value[0] = 255
	if !bytes.Equal(wireBefore, wire) {
		t.Fatal("UnpackHTTPS shares parameter values with wire input")
	}
}

func TestHTTPSDuplicateParameters(t *testing.T) {
	// Python dict assignment replaces the value without moving the first key.
	wire := []byte{0, 1, 0, 0, 5, 0, 1, 'a', 0, 3, 0, 0, 0, 5, 0, 1, 'b'}
	got, err := UnpackHTTPS(wire)
	if err != nil {
		t.Fatal(err)
	}
	want := []HTTPSParam{{Key: 5, Value: []byte{'b'}}, {Key: 3, Value: []byte{}}}
	if diff := gocmp.Diff(want, got.Params); diff != "" {
		t.Fatalf("duplicate parameter semantics (-want +got):\n%s", diff)
	}
}
