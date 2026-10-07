// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/tcp"
)

func TestDNSView(t *testing.T) {
	wire, err := hex.DecodeString("002a0100000100000000000003646e7306676f6f676c650000010001")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		data     []byte
		metadata Metadata
	}{
		"UDP round trip":  {data: wire},
		"TCP round trip":  {data: append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...), metadata: Metadata{TCPMessage: &tcp.Message{}}},
		"HTTP round trip": {data: append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...), metadata: Metadata{HTTPMessage: &httpmsg.Message{}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			before := bytes.Clone(tt.data)
			text, err := (DNS{}).Prettify(tt.data, tt.metadata)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(text, "type: A") || strings.Contains(text, "status_code:") || strings.Contains(text, "timestamp:") {
				t.Fatalf("unexpected DNS YAML:\n%s", text)
			}
			got, err := (DNS{}).Reencode(text, tt.metadata)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.data, got); diff != "" {
				t.Fatalf("DNS round trip:\n%s", diff)
			}
			if !bytes.Equal(before, tt.data) {
				t.Fatal("view modified input")
			}
		})
	}
}

func TestDNSViewErrors(t *testing.T) {
	tests := map[string]struct {
		wire     []byte
		yaml     string
		metadata Metadata
	}{
		"malformed DNS":      {wire: []byte("foobar")},
		"missing TCP prefix": {wire: []byte{0}, metadata: Metadata{TCPMessage: &tcp.Message{}}},
		"malformed YAML":     {yaml: "foo: ["},
		"cyclic YAML":        {yaml: "&loop {questions: *loop}"},
		"oversized YAML":     {yaml: strings.Repeat("x", (1<<20)+1)},
		"excessive nesting":  {yaml: strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65)},
		"scalar document":    {yaml: "42"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if tt.wire != nil {
				if _, err := (DNS{}).Prettify(tt.wire, tt.metadata); err == nil {
					t.Fatal("invalid DNS accepted")
				}
			} else if _, err := (DNS{}).Reencode(tt.yaml, tt.metadata); err == nil {
				t.Fatal("invalid DNS YAML accepted")
			}
		})
	}
}

func TestDNSPriority(t *testing.T) {
	serverPort := func(port int) Metadata {
		f := flow.NewDNSFlow(nil, &connection.Server{Address: &connection.Address{Host: "dns.example", Port: port}}, true)
		return Metadata{Flow: f}
	}
	tests := map[string]struct {
		metadata Metadata
		want     float64
	}{
		"DNS media":  {metadata: Metadata{ContentType: "application/dns-message"}, want: 1},
		"DNS port":   {metadata: serverPort(53), want: 1},
		"mDNS port":  {metadata: serverPort(5353), want: 1},
		"other port": {metadata: serverPort(853)},
		"plain text": {metadata: Metadata{ContentType: "text/plain"}},
		"none":       {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := (DNS{}).RenderPriority(nil, tt.metadata); got != tt.want {
				t.Fatalf("priority = %v, want %v", got, tt.want)
			}
		})
	}
}
