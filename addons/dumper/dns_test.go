// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dumper

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/dns"
)

// TestDNSRecordData pins upstream's ResourceRecord.__str__ output, including
// decoded domain names, ordered HTTPS parameters and invalid-data diagnostics.
func TestDNSRecordData(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		record dns.ResourceRecord
		want   string
	}{
		"success: A address": {
			record: dns.ResourceRecord{Type: dns.TypeA, Data: []byte{8, 8, 8, 8}},
			want:   "8.8.8.8",
		},
		"success: AAAA address": {
			record: dns.ResourceRecord{Type: dns.TypeAAAA, Data: []byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88}},
			want:   "2001:4860:4860::8888",
		},
		"success: TXT text": {
			record: dns.ResourceRecord{Type: dns.TypeTXT, Data: []byte("unittest")},
			want:   "unittest",
		},
		"success: unknown type is hexadecimal": {
			record: dns.ResourceRecord{Type: dns.TypeSOA, Data: []byte{0xde, 0xad, 0xbe, 0xef}},
			want:   "0xdeadbeef",
		},
		"success: CNAME domain name": {
			record: dns.ResourceRecord{Type: dns.TypeCNAME, Data: []byte{3, 'f', 'o', 'o', 0}},
			want:   "foo",
		},
		"success: NS domain name": {
			record: dns.ResourceRecord{Type: dns.TypeNS, Data: []byte{2, 'n', 's', 0}},
			want:   "ns",
		},
		"success: PTR root name": {
			record: dns.ResourceRecord{Type: dns.TypePTR, Data: []byte{0}},
			want:   "",
		},
		"success: HTTPS ordered parameters and numeric key": {
			record: dns.ResourceRecord{Type: dns.TypeHTTPS, Data: []byte{0, 1, 0, 0, 1, 0, 3, 2, 'h', '3', 0, 5, 0, 2, 0, 255, 0, 123, 0, 2, '\'', '"'}},
			want:   `{'target_name': '', 'priority': 1, 'alpn': '\\x02h3', 'ech': '\\x00\\xff', 123: '\'"'}`,
		},
		"error: truncated domain name": {
			record: dns.ResourceRecord{Type: dns.TypeNS, Data: []byte{3, 'n'}},
			want:   "0x036e (invalid NS data)",
		},
		"error: compressed standalone name": {
			record: dns.ResourceRecord{Type: dns.TypePTR, Data: []byte{0xc0, 0}},
			want:   "0xc000 (invalid PTR data)",
		},
		"error: truncated HTTPS parameter": {
			record: dns.ResourceRecord{Type: dns.TypeHTTPS, Data: []byte{0, 1, 0, 0, 1, 0, 2, 'h'}},
			want:   "0x0001000001000268 (invalid HTTPS data)",
		},
		"error: truncated A data": {
			record: dns.ResourceRecord{Type: dns.TypeA, Data: []byte{8, 8}},
			want:   "0x0808 (invalid A data)",
		},
		"error: truncated AAAA data": {
			record: dns.ResourceRecord{Type: dns.TypeAAAA, Data: []byte{0x20}},
			want:   "0x20 (invalid AAAA data)",
		},
		"error: TXT data that is not UTF-8": {
			record: dns.ResourceRecord{Type: dns.TypeTXT, Data: []byte{0xff, 0xfe}},
			want:   "0xfffe (invalid TXT data)",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if diff := gocmp.Diff(tt.want, recordData(&tt.record)); diff != "" {
				t.Fatalf("record data (-upstream +go):\n%s", diff)
			}
		})
	}
}
