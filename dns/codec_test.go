// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestMessagePacking(t *testing.T) {
	// Query and compressed response vectors from test_dns.py::test_packing.
	tests := map[string]struct {
		wire string
		want *Message
	}{
		"query":               {wire: "002a0100000100000000000003646e7306676f6f676c650000010001", want: tDNSReq()},
		"compressed response": {wire: "002a8180000100020000000003646e7306676f6f676c650000010001c00c0001000100000020000408080808c00c0001000100000020000408080404", want: tDNSResp()},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wire, err := hex.DecodeString(tt.wire)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Unpack(wire, tt.want.Timestamp)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("Unpack (-want +got):\n%s", diff)
			}
			packed, err := Pack(got)
			if err != nil {
				t.Fatal(err)
			}
			if name == "query" && !bytes.Equal(packed, wire) {
				t.Fatalf("Pack = %x, want upstream bytes %x", packed, wire)
			}
			again, err := Unpack(packed, tt.want.Timestamp)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(got, again); diff != "" {
				t.Fatalf("round trip (-before +after):\n%s", diff)
			}
			wire[0] ^= 255
			*tt.want.Timestamp = 0
			if got.ID != 42 || *got.Timestamp == 0 {
				t.Fatal("Unpack retained caller-owned input")
			}
		})
	}
}

func TestMessageUnpackErrors(t *testing.T) {
	tests := map[string]struct {
		wire string
		want string
	}{
		"missing header":        {want: "buffer"},
		"missing question":      {wire: "002a01000001000000000000", want: "question #0"},
		"truncated label":       {wire: "002a0100000100000000000003646e7306676f6f", want: "question #0"},
		"compression loop":      {wire: "002a01000001000000000000c00c00010001", want: "loop"},
		"pointer out of bounds": {wire: "002a01000001000000000000ffff00010001", want: "question #0"},
		"illegal label type":    {wire: "002a0100000100000000000040", want: "question #0"},
		"non ASCII label":       {wire: "002a0100000100000000000003ffffff0000010001", want: "illegal"},
		"trailing byte":         {wire: "002a0100000100000000000003646e7306676f6f676c65000001000100", want: "buffer"},
		"truncated record":      {wire: "002a8180000100020000000003646e7306676f6f676c650000010001c00c0001000100000020000408080808c00c00010001000000200004080804", want: "answer #1"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			wire, err := hex.DecodeString(tt.wire)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Unpack(wire, nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) || got != nil {
				t.Fatalf("Unpack = %+v, %v; want nil and %q error", got, err, tt.want)
			}
		})
	}
}

func TestCompressedRecordData(t *testing.T) {
	// Includes opaque malformed CNAME data and fake pointers from the upstream cases.
	tests := map[string]struct {
		wire []byte
		want []byte
	}{
		"SOA pointers": {
			wire: []byte("\x10}\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01\x06google\x03com\x00\x00\x06\x00\x01\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x0c\x00&\x03ns1\xc0\x0c\tdns-admin\xc0\x0c&~gw\x00\x00\x03\x84\x00\x00\x03\x84\x00\x00\x07\x08\x00\x00\x00<\x00\x00)\x02\x00\x00\x00\x00\x00\x00\x00"),
			want: []byte("\x03ns1\x06google\x03com\x00\tdns-admin\x06google\x03com\x00&~gw\x00\x00\x03\x84\x00\x00\x03\x84\x00\x00\x07\x08\x00\x00\x00<"),
		},
		"SOA fake pointers": {
			wire: []byte("\xfc\xc7\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x03com\x00\x00\x06\x00\x01\xc0\x0c\x00\x06\x00\x01\x00\x00\x008\x00&\x03ns1\xc0\x0c\tdns-admin\xc0\x0c&\xd2\xa2\xc2\x00\x00\x03\x84\x00\x00\x03\x84\x00\x00\x07\x08\x00\x00\x00<"),
			want: []byte("\x03ns1\x06google\x03com\x00\tdns-admin\x06google\x03com\x00&\xd2\xa2\xc2\x00\x00\x03\x84\x00\x00\x03\x84\x00\x00\x07\x08\x00\x00\x00<"),
		},
		"A bytes are not pointers": {
			wire: []byte("\x98A\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01\x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00/\x00\x04\xd8:\xc4\xae\x00\x00)\x02\x00\x00\x00\x00\x00\x00\x00"),
			want: []byte("\xd8:\xc4\xae"),
		},
		"malformed CNAME remains opaque": {
			wire: []byte("V\x1a\x81\x80\x00\x01\x00\x01\x00\x01\x00\x01\x05alive\x06github\x03com\x00\x00\x10\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x0b\xc6\x00\x07\x99live\xc0\x12\xc0\x12\x00\x06\x00\x01\x00\x00\x03\x84\x00H\x07ns-1707\tawsdns-21\x02co\x02uk\x00\x11awsdns-hostmaster\x06amazon\xc0\x19\x00\x00\x00\x01\x00\x00\x1c \x00\x00\x03\x84\x00\x12u\x00\x00\x01Q\x80\x00\x00)\x02\x00\x00\x00\x00\x00\x00\x00"),
			want: []byte("\x99live\x06github\x03com\x00"),
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Unpack(tt.wire, nil)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, got.Answers[0].Data); diff != "" {
				t.Fatalf("RDATA (-want +got):\n%s", diff)
			}
			packed, err := Pack(got)
			if err != nil {
				t.Fatal(err)
			}
			again, err := Unpack(packed, nil)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(got, again); diff != "" {
				t.Fatalf("repacked RDATA (-before +after):\n%s", diff)
			}
		})
	}
}

func FuzzUnpack(f *testing.F) {
	f.Add([]byte{0, 42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1})
	f.Add(expansionMessage(5000))
	f.Add([]byte{0, 42, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte("\x00*\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03dns\x06google\x00\x00\x01\x00\x01"))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Both decoders must reject malformed input without a panic.
		_, _ = UnpackHTTPS(data)
		message, err := Unpack(data, nil)
		if err != nil {
			return
		}
		before := message.Clone()
		_, _ = Pack(message)
		if diff := gocmp.Diff(before, message); diff != "" {
			t.Fatalf("Pack mutated decoded state:\n%s", diff)
		}
	})
}
