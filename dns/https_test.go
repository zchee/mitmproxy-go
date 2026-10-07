// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"bytes"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestHTTPSPacking(t *testing.T) {
	// test_https_records.py::test_pack/test_unpack and test_dns.py ALPN/ECH vectors.
	tests := map[string]struct {
		record HTTPSRecord
		wire   []byte
	}{
		"root":                        {record: HTTPSRecord{Priority: 1, Params: []HTTPSParam{}}, wire: []byte{0, 1, 0}},
		"ALPN":                        {record: HTTPSRecord{Priority: 1, TargetName: "example.org", Params: []HTTPSParam{{Key: 1, Value: []byte("\x02h2\x02h3")}}}, wire: []byte("\x00\x01\x07example\x03org\x00\x00\x01\x00\x06\x02h2\x02h3")},
		"unknown unsorted parameters": {record: HTTPSRecord{Priority: -1, TargetName: "example.org", Params: []HTTPSParam{{Key: 111, Value: []byte{0}}, {Key: 2, Value: []byte{}}}}, wire: []byte("\xff\xff\x07example\x03org\x00\x00o\x00\x01\x00\x00\x02\x00\x00")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := PackHTTPS(tt.record)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.wire, got); diff != "" {
				t.Fatalf("PackHTTPS (-want +got):\n%s", diff)
			}
			record, err := UnpackHTTPS(tt.wire)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.record, record); diff != "" {
				t.Fatalf("UnpackHTTPS (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHTTPSUnpackErrors(t *testing.T) {
	tests := map[string]struct {
		data []byte
		want string
	}{
		"empty":                    {want: "buffer"},
		"invalid label":            {data: []byte("\x00\x01\x07exampl\x87\x03com\x00\x00\x01\x00\x06\x02h2\x02h3"), want: "illegal"},
		"truncated parameter":      {data: []byte("\x00\x01\x07example\x03com\x00\x00\x01\x00\x06\x02h2"), want: "25 bytes"},
		"truncated label":          {data: []byte("\x00\x01\x07exa"), want: "label buffer"},
		"compressed target":        {data: []byte{0, 1, 0xc0, 0}, want: "pointer"},
		"partial parameter header": {data: []byte{0, 1, 0, 1}, want: "buffer"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := UnpackHTTPS(tt.data)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("UnpackHTTPS = %v, want %q error", err, tt.want)
			}
		})
	}
}

func TestHTTPSRecordHelpers(t *testing.T) {
	r := ResourceRecord{Data: []byte("\x00\x01\x07example\x03org\x00\x00\x03\x00\x02\x01\xbb")}
	alpn, err := r.HTTPSALPN()
	if err != nil || alpn != nil {
		t.Fatalf("absent ALPN = %v, %v", alpn, err)
	}
	if err := r.SetHTTPSALPN([][]byte{[]byte("h2"), []byte("h3")}); err != nil {
		t.Fatal(err)
	}
	alpn, err = r.HTTPSALPN()
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([][]byte{[]byte("h2"), []byte("h3")}, alpn); diff != "" {
		t.Fatalf("ALPN (-want +got):\n%s", diff)
	}
	alpn[0][0] = 'x'
	if bytes.Contains(r.Data, []byte("x2")) {
		t.Fatal("ALPN getter shares RDATA")
	}
	ech, err := r.HTTPSECH()
	if err != nil || ech != nil {
		t.Fatalf("absent ECH = %v, %v", ech, err)
	}
	value := "dGVzdHN0cmluZwo="
	if err := r.SetHTTPSECH(&value); err != nil {
		t.Fatal(err)
	}
	ech, err = r.HTTPSECH()
	if err != nil || ech == nil || *ech != value {
		t.Fatalf("ECH = %v, %v", ech, err)
	}
	if err := r.SetHTTPSALPN(nil); err != nil {
		t.Fatal(err)
	}
	if err := r.SetHTTPSECH(nil); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]byte("\x00\x01\x07example\x03org\x00\x00\x03\x00\x02\x01\xbb"), r.Data); diff != "" {
		t.Fatalf("other parameter not preserved:\n%s", diff)
	}
	tests := map[string]struct {
		set func(*ResourceRecord) error
	}{
		"long ALPN":      {set: func(r *ResourceRecord) error { return r.SetHTTPSALPN([][]byte{bytes.Repeat([]byte{'a'}, 256)}) }},
		"bad ECH base64": {set: func(r *ResourceRecord) error { return r.SetHTTPSECH(new("a")) }},
		"invalid domain": {set: func(r *ResourceRecord) error { return r.SetDomainName("hello..world") }},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			before := bytes.Clone(r.Data)
			if err := tt.set(&r); err == nil {
				t.Fatal("invalid setter succeeded")
			}
			if diff := gocmp.Diff(before, r.Data); diff != "" {
				t.Fatalf("failed setter modified RDATA:\n%s", diff)
			}
		})
	}
}
