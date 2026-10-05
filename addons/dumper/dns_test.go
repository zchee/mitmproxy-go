// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dumper

import (
	"testing"

	"github.com/zchee/mitmproxy-go/dns"
)

// TestDNSRecordData checks the answer rendering behind the dns_response
// output: upstream's str() for A, AAAA and TXT records and the
// hexadecimal fallback, the invalid-data text, and the type-name
// placeholder for records whose data needs the DNS wire codec
// (docs/compat.md).
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
		"success: codec-dependent type renders as its name": {
			record: dns.ResourceRecord{Type: dns.TypeCNAME, Data: []byte{3, 'f', 'o', 'o', 0}},
			want:   "CNAME",
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
			if got := recordData(&tt.record); got != tt.want {
				t.Fatalf("recordData() = %q, want %q", got, tt.want)
			}
		})
	}
}
