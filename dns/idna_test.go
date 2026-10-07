// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"bytes"
	"testing"
)

func TestIDNAMappings(t *testing.T) {
	tests := map[string]struct {
		input   string
		ascii   string
		decoded string
	}{
		"punycode":       {input: "bücher", ascii: "xn--bcher-kva", decoded: "bücher"},
		"sharp s":        {input: "faß", ascii: "fass", decoded: "fass"},
		"joiner removal": {input: "a\U0000200Db", ascii: "ab", decoded: "ab"},
		// Python's IDNA2003/Unicode 3.2 encodes U+1E9E as "xn--kkg".
		"capital sharp s": {input: "ẞ", ascii: "ss", decoded: "ss"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			record := ResourceRecord{}
			if err := record.SetDomainName(tt.input); err != nil {
				t.Fatal(err)
			}
			want := append([]byte{byte(len(tt.ascii))}, []byte(tt.ascii)...)
			want = append(want, 0)
			if !bytes.Equal(want, record.Data) {
				t.Fatalf("SetDomainName(%q) = %x, want %x", tt.input, record.Data, want)
			}
			got, err := record.DomainName()
			if err != nil || got != tt.decoded {
				t.Fatalf("DomainName() = %q, %v; want %q", got, err, tt.decoded)
			}
		})
	}
}
