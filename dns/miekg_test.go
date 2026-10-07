// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestMiekgHeader(t *testing.T) {
	// Wire expectations follow mitmproxy/dns.py DNSMessage.packed.
	tests := map[string]struct {
		message Message
		want    []byte
	}{
		"query":                     {message: Message{ID: 0x1234, Query: true, RecursionDesired: true, Questions: []Question{{}}}, want: []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}},
		"response flags and counts": {message: Message{ID: 65535, OpCode: 15, AuthoritativeAnswer: true, Truncation: true, RecursionDesired: true, RecursionAvailable: true, Reserved: 7, ResponseCode: 15, Questions: []Question{{}}, Answers: []ResourceRecord{{}, {}}, Authorities: []ResourceRecord{{}}, Additionals: []ResourceRecord{{}}}, want: []byte{255, 255, 255, 255, 0, 1, 0, 2, 0, 1, 0, 1}},
		"empty root response":       {want: []byte{0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := packHeader(&tt.message)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("DNS header (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMiekgHeaderBounds(t *testing.T) {
	tests := map[string]struct {
		message *Message
		field   string
	}{
		"nil":                       {field: "nil"},
		"negative id":               {message: &Message{ID: -1}, field: "id"},
		"large id":                  {message: &Message{ID: 65536}, field: "id"},
		"negative opcode":           {message: &Message{OpCode: -1}, field: "op_code"},
		"large opcode":              {message: &Message{OpCode: 16}, field: "op_code"},
		"negative reserved":         {message: &Message{Reserved: -1}, field: "reserved"},
		"large reserved":            {message: &Message{Reserved: 8}, field: "reserved"},
		"negative rcode":            {message: &Message{ResponseCode: -1}, field: "response_code"},
		"large rcode":               {message: &Message{ResponseCode: 16}, field: "response_code"},
		"question count overflow":   {message: &Message{Questions: make([]Question, 65536)}, field: "question"},
		"answer count overflow":     {message: &Message{Answers: make([]ResourceRecord, 65536)}, field: "answer"},
		"authority count overflow":  {message: &Message{Authorities: make([]ResourceRecord, 65536)}, field: "authority"},
		"additional count overflow": {message: &Message{Additionals: make([]ResourceRecord, 65536)}, field: "additional"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := packHeader(tt.message)
			if err == nil || !strings.Contains(err.Error(), tt.field) || got != nil {
				t.Fatalf("packHeader() = %x, %v; want nil bytes and %q error", got, err, tt.field)
			}
		})
	}
}
