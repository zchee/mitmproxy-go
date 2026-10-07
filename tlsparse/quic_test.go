// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsparse

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func quicVector(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/quic/" + name + ".hex")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestQUICClientHelloVectors(t *testing.T) {
	// py:test/mitmproxy/proxy/layers/quic/test__client_hello_parser.py:
	// test_input and test_no_return; test__stream_layers.py:test_fragmented_client_hello.
	packet := quicVector(t, "client_hello")
	first := quicVector(t, "fragmented_client_hello1")
	second := quicVector(t, "fragmented_client_hello2")
	// Real quic-go v0.63.0 capture, generated once with Go 1.27.1; the
	// generator path and date-command capture time are in testdata/quic/README.md.
	capturedFirst := quicVector(t, "quic_go_initial_1")
	capturedSecond := quicVector(t, "quic_go_initial_2")
	tests := map[string]struct {
		datagrams [][]byte
		wantSNI   string
		wantErr   error
	}{
		"success: captured two Initial datagrams": {datagrams: [][]byte{capturedFirst, capturedSecond}, wantSNI: "two-datagram.example"},
		"success: captured Initials reordered":    {datagrams: [][]byte{capturedSecond, capturedFirst}, wantSNI: "two-datagram.example"},
		"success: pinned single Initial":          {datagrams: [][]byte{packet}, wantSNI: "example.com"},
		"success: fragmented in order":            {datagrams: [][]byte{first, second}, wantSNI: "localhost"},
		"success: fragmented out of order":        {datagrams: [][]byte{second, first}, wantSNI: "localhost"},
		"success: retransmitted fragment":         {datagrams: [][]byte{first, first, second}, wantSNI: "localhost"},
		"error: truncated encrypted payload":      {datagrams: [][]byte{append(bytes.Clone(packet[:183]), make([]byte, 9)...)}, wantErr: ErrMalformed},
		"error: not Initial":                      {datagrams: [][]byte{{0x5c, 0x73, 0xd8, 0xd8}}, wantErr: ErrMalformed},
		"error: damaged encrypted payload":        {datagrams: [][]byte{append(append(bytes.Clone(packet[:1200]), 0), packet[1200:]...)}, wantErr: ErrMalformed},
		"error: unsupported version":              {datagrams: [][]byte{append([]byte{packet[0], 0, 0, 0, 3}, packet[5:]...)}, wantErr: ErrMalformed},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var parser QUICClientHelloParser
			var hello *ClientHello
			var err error
			for i, packet := range tt.datagrams {
				hello, err = parser.Feed(packet)
				if tt.wantErr == nil && i < len(tt.datagrams)-1 && (hello != nil || err != nil) {
					t.Fatalf("fragment %d completed early: (%v, %v)", i, hello, err)
				}
				if err != nil || hello != nil {
					break
				}
				if i == len(tt.datagrams)-1 {
					t.Fatal("all datagrams consumed without a complete hello or error")
				}
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Feed error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil {
				if hello == nil {
					t.Fatal("missing hello")
				}
				if diff := gocmp.Diff(tt.wantSNI, hello.SNI()); diff != "" {
					t.Errorf("SNI mismatch (-want +got):\n%s", diff)
				}
			}
			again, againErr := parser.Feed(nil)
			if again != hello || againErr != err {
				t.Fatalf("terminal result not retained: (%p, %v), want (%p, %v)", again, againErr, hello, err)
			}
		})
	}
}

func TestQUICInitialClassifier(t *testing.T) {
	tests := map[string]struct {
		data []byte
		want bool
	}{
		"success: v1":            {data: []byte{0xc0, 0, 0, 0, 1}, want: true},
		"success: v2":            {data: []byte{0xd0, 0x6b, 0x33, 0x43, 0xcf}, want: true},
		"error: truncated":       {data: []byte{0xc0, 0, 0, 0}},
		"error: short header":    {data: []byte{0x40, 0, 0, 0, 1}},
		"error: fixed bit clear": {data: []byte{0x80, 0, 0, 0, 1}},
		"error: v1 handshake":    {data: []byte{0xe0, 0, 0, 0, 1}},
		"error: v2 retry":        {data: []byte{0xc0, 0x6b, 0x33, 0x43, 0xcf}},
		"error: unknown version": {data: []byte{0xc0, 0, 0, 0, 3}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := StartsLikeQUICInitial(tt.data); got != tt.want {
				t.Errorf("StartsLikeQUICInitial(%x) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}
