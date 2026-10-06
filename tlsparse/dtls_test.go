// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsparse

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// These vectors and cases come from test/mitmproxy/proxy/layers/test_tls.py.
const (
	dtlsHelloWithoutExtensions = "010000360000000000000036fefd62be32f048777da890ddd213b0cb8dc3e2903f88dda1cd5f67808e1169110e840000000cc02bc02fc00ac014c02cc03001000000"
	dtlsHelloWithExtensions    = "16fefd00000000000000000085010000790000000000000079fefd62bf0e0bf809df43e7669197be831919878b1a72c07a584d3c0a8ca6665878010000000cc02bc02fc00ac014c02cc03001000043000d0010000e0403050306030401050106010807ff01000100000a00080006001d00170018000b000201000017000000000010000e00000b6578616d706c652e636f6d"
)

func dtlsHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func dtlsRecord(body []byte) []byte {
	b := []byte{0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0}
	b = binary.BigEndian.AppendUint16(b, uint16(len(body))) //nolint:gosec // Test messages fit the record length field.
	return append(b, body...)
}

func TestDTLSRecordContents(t *testing.T) {
	data := dtlsHex(t, "16fefd00000000000000000002beef16fefd00000000000000000001ff")
	tests := map[string]struct {
		data []byte
		want [][]byte
		err  error
	}{
		"success: upstream records": {data, [][]byte{{0xbe, 0xef}, {0xff}}, nil},
		"error: non-DTLS record":    {[]byte("GET /this-will-cause-error"), nil, ErrMalformed},
		"error: empty record":       {dtlsHex(t, "16fefd00000000000000000000"), nil, ErrMalformed},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var got [][]byte
			var gotErr error
			for body, err := range DTLSHandshakeRecordContents(tt.data) {
				if err != nil {
					gotErr = err
					break
				}
				got = append(got, body)
			}
			if !errors.Is(gotErr, tt.err) {
				t.Fatalf("error = %v, want %v", gotErr, tt.err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	for i := range 15 {
		for body, err := range DTLSHandshakeRecordContents(data[:i]) {
			t.Fatalf("truncated prefix %d yielded %x, %v", i, body, err)
		}
	}
}

func TestGetDTLSClientHello(t *testing.T) {
	hello := dtlsHex(t, dtlsHelloWithoutExtensions)
	single := dtlsRecord(hello)
	split := append(dtlsRecord(hello[:32]), dtlsRecord(hello[32:])...)
	tests := map[string]struct {
		data []byte
		want []byte
	}{
		"success: upstream single record":              {single, hello},
		"success: upstream split records":              {split, hello},
		"success: incomplete upstream":                 {split[:42], nil},
		"success: retransmission after complete hello": {append(bytes.Clone(single), single...), hello},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetDTLSClientHello(tt.data)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	for i := range len(single) {
		got, err := GetDTLSClientHello(single[:i])
		if got != nil || err != nil {
			t.Fatalf("prefix %d: %x, %v", i, got, err)
		}
	}
	oversized := dtlsRecord([]byte{1, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0})
	if _, err := GetDTLSClientHello(oversized); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized length: %v", err)
	}
}

func TestParseDTLSClientHello(t *testing.T) {
	data := dtlsHex(t, dtlsHelloWithExtensions)
	invalid := append(bytes.Clone(data[:len(data)-16]), dtlsHex(t, "000e000020000000000000000000000000")...)
	noExt := dtlsHex(t, dtlsHelloWithoutExtensions)
	tests := map[string]struct {
		data       []byte
		sni        string
		incomplete bool
		err        error
	}{
		"success: upstream SNI":                                  {data, "example.com", false, nil},
		"success: upstream incomplete":                           {data[:50], "", true, nil},
		"error: upstream invalid SNI length":                     {invalid, "", false, ErrMalformed},
		"success: no extensions":                                 {dtlsRecord(noExt), "", false, nil},
		"error: reordered record bodies":                         {append(dtlsRecord(noExt[32:]), dtlsRecord(noExt[:32])...), "", false, ErrTooLarge},
		"error: retransmission during incomplete hello":          {append(append(dtlsRecord(noExt[:32]), dtlsRecord(noExt[:32])...), dtlsRecord(noExt[32:])...), "", false, ErrMalformed},
		"error: genuine handshake fragments are not reassembled": {dtlsRecord(append(dtlsHex(t, "010000360000000000000014"), noExt[12:32]...)), "", false, ErrMalformed},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ParseDTLSClientHello(tt.data)
			if !errors.Is(err, tt.err) {
				t.Fatalf("error = %v, want %v", err, tt.err)
			}
			if tt.err != nil {
				return
			}
			if tt.incomplete {
				if got != nil {
					t.Fatal("incomplete hello parsed")
				}
				return
			}
			if got == nil {
				t.Fatal("complete hello not parsed")
			}
			if diff := cmp.Diff(tt.sni, got.SNI()); diff != "" {
				t.Fatal(diff)
			}
			if diff := cmp.Diff([]uint16{0xc02b, 0xc02f, 0xc00a, 0xc014, 0xc02c, 0xc030}, got.CipherSuites()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestStartsLikeDTLSRecord(t *testing.T) {
	tests := map[string]struct {
		data []byte
		want bool
	}{
		"success: DTLS 1.0":      {[]byte{0x16, 0xfe, 0xfe}, true},
		"success: DTLS 1.2":      {[]byte{0x16, 0xfe, 0xfd}, true},
		"error: DTLS 1.3 record": {[]byte{0x16, 0xfe, 0xfc}, false},
		"error: short":           {[]byte{0x16, 0xfe}, false},
		"error: TLS":             {[]byte{0x16, 3, 3}, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := StartsLikeDTLSRecord(tt.data); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClientHelloDTLSRawBytes(t *testing.T) {
	raw := dtlsHex(t, dtlsHelloWithoutExtensions)[dtlsHandshakeHeaderLen:]
	tlsBody := append(bytes.Clone(raw[:35]), raw[36:]...)
	tlsHello, err := NewClientHello(tlsBody)
	if err != nil {
		t.Fatal(err)
	}
	dtlsHello, err := ParseDTLSClientHello(dtlsRecord(dtlsHex(t, dtlsHelloWithoutExtensions)))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		hello *ClientHello
		dtls  bool
		body  []byte
	}{
		"success: TLS":  {tlsHello, false, tlsBody},
		"success: DTLS": {dtlsHello, true, raw},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tt.hello.IsDTLS(); got != tt.dtls {
				t.Fatalf("IsDTLS = %v, want %v", got, tt.dtls)
			}
			if diff := cmp.Diff(tt.body, tt.hello.RawBytes(false)); diff != "" {
				t.Fatal(diff)
			}
			wrapped := tt.hello.RawBytes(true)
			if tt.dtls && wrapped != nil || !tt.dtls && wrapped == nil {
				t.Fatalf("wrapped record = %x, DTLS = %v", wrapped, tt.dtls)
			}
			copy := tt.hello.RawBytes(false)
			copy[0] ^= 0xff
			if diff := cmp.Diff(tt.body, tt.hello.RawBytes(false)); diff != "" {
				t.Fatalf("RawBytes leaked mutable storage: %s", diff)
			}
		})
	}
}

func FuzzDTLSClientHello(f *testing.F) {
	for _, seed := range []string{dtlsHelloWithExtensions, "16fefd00000000000000000042" + dtlsHelloWithoutExtensions, "16fefd00000000000000000000"} {
		b, err := hex.DecodeString(seed)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		hello, err := ParseDTLSClientHello(data)
		if err != nil && !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrTooLarge) {
			t.Fatalf("unexpected error: %v", err)
		}
		if hello != nil {
			hello.SNI()
			hello.ALPNProtocols()
			hello.Extensions()
			hello.RawBytes(false)
		}
	})
}
