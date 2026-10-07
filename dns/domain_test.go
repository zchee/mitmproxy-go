// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"bytes"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestDomainNames(t *testing.T) {
	// domain_names.py::test_pack/test_unpack, plus IDNA and ownership cases.
	tests := map[string]struct {
		name string
		wire []byte
	}{
		"root":               {wire: []byte{0}},
		"ASCII":              {name: "www.example.org", wire: []byte("\x03www\x07example\x03org\x00")},
		"uppercase retained": {name: "EXAMPLE.org", wire: []byte("\x07EXAMPLE\x03org\x00")},
		"IDNA":               {name: "bücher.example", wire: []byte("\x0dxn--bcher-kva\x07example\x00")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := ResourceRecord{}
			if err := r.SetDomainName(tt.name); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.wire, r.Data); diff != "" {
				t.Fatalf("domain wire (-want +got):\n%s", diff)
			}
			got, err := r.DomainName()
			if err != nil || got != tt.name {
				t.Fatalf("DomainName = %q, %v; want %q", got, err, tt.name)
			}
		})
	}
}

func TestDomainNameErrors(t *testing.T) {
	tests := map[string]struct {
		wire []byte
		want string
	}{
		"trailing byte":      {wire: []byte("\x03www\x07example\x03org\x00\xff"), want: "17 bytes"},
		"compressed RDATA":   {wire: []byte("\x03www\x07example\x03org\xc0\x00"), want: "pointer"},
		"truncated label":    {wire: []byte{10}, want: "10 bytes"},
		"large label":        {wire: append([]byte{64}, bytes.Repeat([]byte{'a'}, 64)...), want: "length 64"},
		"illegal characters": {wire: []byte{3, 255, 255, 255, 0}, want: "illegal characters"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := ResourceRecord{Data: tt.wire}
			_, err := r.DomainName()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("DomainName error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRecordWireRoundTrips(t *testing.T) {
	tests := map[string]struct {
		typ  int
		data []byte
	}{
		"A":          {typ: TypeA, data: []byte{1, 2, 3, 4}},
		"AAAA":       {typ: TypeAAAA, data: append(make([]byte, 15), 1)},
		"NS":         {typ: TypeNS, data: []byte("\x02ns\x07example\x00")},
		"CNAME":      {typ: TypeCNAME, data: []byte("\x05alias\x07example\x00")},
		"PTR":        {typ: TypePTR, data: []byte("\x05alias\x07example\x00")},
		"TXT":        {typ: TypeTXT, data: []byte("unicode text 😀")},
		"SOA opaque": {typ: TypeSOA, data: []byte{0, 1, 2, 3}},
		"HTTPS":      {typ: TypeHTTPS, data: []byte("\x00\x01\x07example\x03com\x00")},
		"SVCB":       {typ: TypeSVCB, data: []byte("\x00\x01\x07example\x03com\x00")},
		"unknown":    {typ: 65000, data: []byte{255, 255}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			message := tDNSReq()
			r := ResourceRecord{Name: "example.org", Type: tt.typ, Class: ClassIN, TTL: 60, Data: tt.data}
			message.Answers = []ResourceRecord{r}
			message.Authorities = []ResourceRecord{r.Clone()}
			message.Additionals = []ResourceRecord{r.Clone()}
			before := message.Clone()
			wire, err := Pack(message)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Unpack(wire, message.Timestamp)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(message, got); diff != "" {
				t.Fatalf("RR round trip (-want +got):\n%s", diff)
			}
			wireBefore := bytes.Clone(wire)
			got.Answers[0].Data[0] ^= 255
			if diff := gocmp.Diff(wireBefore, wire); diff != "" {
				t.Fatalf("decoded RDATA aliases wire input:\n%s", diff)
			}
			if diff := gocmp.Diff(before, message); diff != "" {
				t.Fatalf("codec mutated caller state:\n%s", diff)
			}
		})
	}
}
