// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsparse

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func quicHex(t testing.TB, text string) []byte {
	t.Helper()
	out, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestQUICInitialProtection(t *testing.T) {
	// RFC 9001 appendix A.1/A.2 and RFC 9369 appendix A.1/A.2 supply
	// independent encrypted known answers, not ciphertext from this parser.
	// Python pins aioquic 1.2.0 (py:pyproject.toml:34), whose
	// aioquic/quic/configuration.py:115-120 supported_versions lists v1 and v2.
	tests := map[string]struct {
		name string
	}{
		"success: RFC v1": {name: "rfc9001_client_initial"},
		"success: RFC v2": {name: "rfc9369_client_initial"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var p QUICClientHelloParser
			hello, err := p.Feed(quicVector(t, tt.name))
			if err != nil || hello == nil {
				t.Fatalf("Feed RFC packet = (%v, %v)", hello, err)
			}
			if diff := gocmp.Diff("example.com", hello.SNI()); diff != "" {
				t.Errorf("SNI (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff([][]byte{[]byte("alpn")}, hello.ALPNProtocols()); diff != "" {
				t.Errorf("ALPN (-want +got):\n%s", diff)
			}
		})
	}
	// RFC 9001 A.1/A.2: verify the independently specified IV and HP mask.
	hp, _, iv, err := quicInitialKeys(quicVersion1, quicHex(t, "8394c8f03e515708"))
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(quicHex(t, "fa044b2f42a3fd3b46fb255c"), iv); diff != "" {
		t.Errorf("Initial IV (-want +got):\n%s", diff)
	}
	var mask [16]byte
	hp.Encrypt(mask[:], quicHex(t, "d1b1c98dd7689fb8ec11d242b123dc9b"))
	if diff := gocmp.Diff(quicHex(t, "437b9aec36"), mask[:5]); diff != "" {
		t.Errorf("Header protection mask (-want +got):\n%s", diff)
	}
}

func appendQUICInt(data []byte, value uint64) []byte {
	switch {
	case value < 1<<6:
		return append(data, byte(value))
	case value < 1<<14:
		return binary.BigEndian.AppendUint16(data, uint16(value)|0x4000) //nolint:gosec // Range checked.
	case value < 1<<30:
		return binary.BigEndian.AppendUint32(data, uint32(value)|0x80000000) //nolint:gosec // Range checked.
	default:
		return binary.BigEndian.AppendUint64(data, value|0xc000000000000000)
	}
}

func quicCryptoFrame(offset uint64, data []byte) []byte {
	out := appendQUICInt([]byte{6}, offset)
	out = appendQUICInt(out, uint64(len(data)))
	return append(out, data...)
}

func quicTestInitial(t testing.TB, payload []byte, pn uint32, pnLen int, version uint32) []byte {
	t.Helper()
	dcid := quicHex(t, "8394c8f03e515708")
	hp, aead, iv, err := quicInitialKeys(version, dcid)
	if err != nil {
		t.Fatal(err)
	}
	first := byte(0xc0)
	if version == quicVersion2 {
		first = 0xd0
	}
	header := binary.BigEndian.AppendUint32([]byte{first | byte(pnLen-1)}, version) //nolint:gosec // Test sizes 1..4.
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, 0, 0) // SCID and token lengths.
	// Pad the encrypted frame payload, not the trailing datagram.
	size := max(len(payload), 1200-len(header)-2-pnLen-aead.Overhead())
	frames := make([]byte, size)
	copy(frames, payload)
	header = appendQUICInt(header, uint64(pnLen+size+aead.Overhead()))
	pnOffset := len(header)
	for i := pnLen - 1; i >= 0; i-- {
		header = append(header, byte(pn>>(i*8)))
	}
	nonce := bytes.Clone(iv)
	for i := range 4 {
		nonce[len(nonce)-1-i] ^= byte(pn >> (i * 8))
	}
	packet := aead.Seal(header, nonce, frames, header)
	var mask [16]byte
	hp.Encrypt(mask[:], packet[pnOffset+4:pnOffset+20])
	packet[0] ^= mask[0] & 0x0f
	for i := range pnLen {
		packet[pnOffset+i] ^= mask[i+1]
	}
	return packet
}

func TestQUICInitialAdversarial(t *testing.T) {
	// Real invalid handshake bytes replace the monkeypatch-only upstream
	// TestParseClientHello.test_invalid; illegal Initial frame bytes replace
	// TestParseClientHello.test_connection_error. Neither needs a fake endpoint.
	tests := map[string]struct {
		payload []byte
		wantErr error
	}{
		"error: truncated CRYPTO length":         {payload: []byte{6, 0, 0xff}, wantErr: ErrMalformed},
		"error: CRYPTO declared bytes absent":    {payload: appendQUICInt([]byte{6, 0}, 60000), wantErr: ErrMalformed},
		"error: offset past bound":               {payload: quicCryptoFrame(MaxClientHelloSize+1, []byte{1}), wantErr: ErrTooLarge},
		"error: offset and length past bound":    {payload: quicCryptoFrame(MaxClientHelloSize, []byte{1}), wantErr: ErrTooLarge},
		"error: invalid ClientHello body":        {payload: quicCryptoFrame(0, []byte{1, 0, 0, 1, 0}), wantErr: ErrMalformed},
		"error: wrong handshake type":            {payload: quicCryptoFrame(0, []byte{2, 0, 0, 1, 0}), wantErr: ErrMalformed},
		"error: handshake declared too large":    {payload: quicCryptoFrame(0, []byte{1, 1, 0, 0}), wantErr: ErrTooLarge},
		"error: forbidden Initial STREAM frame":  {payload: []byte{8}, wantErr: ErrMalformed},
		"error: ACK range underflow":             {payload: []byte{2, 0, 0, 1, 0, 0, 0}, wantErr: ErrMalformed},
		"error: ACK first range exceeds largest": {payload: []byte{2, 0, 0, 0, 1}, wantErr: ErrMalformed},
		"error: ACK excessive range count":       {payload: appendQUICInt([]byte{2, 0, 0}, 1<<40), wantErr: ErrMalformed},
		"error: connection close":                {payload: []byte{0x1c}, wantErr: ErrMalformed},
		"success: PING and ACK":                  {payload: []byte{1, 2, 10, 0, 1, 2, 1, 2}},
		"success: ACK ECN":                       {payload: []byte{3, 0, 0, 0, 0, 0, 0, 0}},
		"success: zero-length CRYPTO":            {payload: quicCryptoFrame(0, nil)},
		"success: sparse CRYPTO":                 {payload: quicCryptoFrame(MaxClientHelloSize-1, []byte{42})},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var p QUICClientHelloParser
			hello, err := p.Feed(quicTestInitial(t, tt.payload, 0, 2, quicVersion1))
			if !errors.Is(err, tt.wantErr) || hello != nil {
				t.Fatalf("Feed = (%v, %v), want (nil, %v)", hello, err, tt.wantErr)
			}
			retained := 0
			for _, f := range p.fragments {
				retained += len(f.data)
			}
			if retained > len(tt.payload) {
				t.Errorf("sparse storage = %d bytes, input frame = %d bytes", retained, len(tt.payload))
			}
		})
	}
}

func TestQUICCryptoReassembly(t *testing.T) {
	// The payload body is the independently specified RFC 9001 A.2 hello.
	var reference QUICClientHelloParser
	hello, err := reference.Feed(quicVector(t, "rfc9001_client_initial"))
	if err != nil || hello == nil {
		t.Fatalf("RFC vector = (%v, %v)", hello, err)
	}
	body := hello.RawBytes(false)
	msg := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	tests := map[string]struct {
		frames  [][]byte
		wantErr error
	}{
		"success: split header and body": {frames: [][]byte{quicCryptoFrame(2, msg[2:]), quicCryptoFrame(0, msg[:2])}},
		"success: partially overlapping": {frames: [][]byte{quicCryptoFrame(0, msg[:100]), quicCryptoFrame(80, msg[80:])}},
		"success: gap filled last":       {frames: [][]byte{quicCryptoFrame(0, msg[:50]), quicCryptoFrame(100, msg[100:]), quicCryptoFrame(50, msg[50:100])}},
		"error: conflicting overlap":     {frames: [][]byte{quicCryptoFrame(0, msg[:100]), quicCryptoFrame(80, bytes.Repeat([]byte{0xff}, 30))}, wantErr: ErrMalformed},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var p QUICClientHelloParser
			for i, frame := range tt.frames {
				packet := quicTestInitial(t, frame, uint32(i), 1+i%4, quicVersion1) //nolint:gosec // Small table.
				got, err := p.Feed(packet)
				clear(packet) // Feed must not keep input aliases.
				if i < len(tt.frames)-1 && (got != nil || err != nil) {
					t.Fatalf("premature completion at fragment %d: (%v, %v)", i, got, err)
				}
				if i == len(tt.frames)-1 {
					if !errors.Is(err, tt.wantErr) {
						t.Fatalf("Feed error = %v, want %v", err, tt.wantErr)
					}
					if err == nil && (got == nil || got.SNI() != "example.com") {
						t.Fatalf("completed hello = %v, want RFC example.com", got)
					}
				}
			}
		})
	}
}

func TestQUICParserBounds(t *testing.T) {
	tests := map[string]struct {
		datagrams int
		fragment  bool
	}{
		"error: datagram count":        {datagrams: maxQUICDatagrams + 1},
		"error: sparse interval count": {datagrams: 1, fragment: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var p QUICClientHelloParser
			payload := []byte{1}
			if tt.fragment {
				payload = nil
				for i := range maxQUICFragments + 1 {
					payload = append(payload, quicCryptoFrame(uint64(8+i*2), []byte{42})...)
				}
			}
			var err error
			for i := range tt.datagrams {
				_, err = p.Feed(quicTestInitial(t, payload, uint32(i), 2, quicVersion1)) //nolint:gosec // Count bounded above.
				if i < tt.datagrams-1 && err != nil {
					t.Fatalf("unexpected early error at %d: %v", i, err)
				}
			}
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("bound error = %v, want ErrTooLarge", err)
			}
		})
	}
	var p QUICClientHelloParser
	if _, err := p.Feed(make([]byte, maxQUICDatagramSize+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized datagram error = %v, want ErrTooLarge", err)
	}
}

func TestQUICPacketNumber(t *testing.T) {
	tests := map[string]struct {
		truncated uint64
		size      int
		expected  uint64
		want      uint64
	}{
		"success: RFC 9000 appendix A.3": {truncated: 0x9b32, size: 2, expected: 0xa82f30eb, want: 0xa82f9b32},
		"success: next window":           {truncated: 0, size: 1, expected: 255, want: 256},
		"success: previous window":       {truncated: 255, size: 1, expected: 256, want: 255},
		"success: initial number":        {truncated: 2, size: 4, want: 2},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := quicPacketNumber(tt.truncated, tt.size, tt.expected); got != tt.want {
				t.Errorf("packet number = %#x, want %#x", got, tt.want)
			}
		})
	}
}
