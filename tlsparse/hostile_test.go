// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsparse_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"slices"
	"testing"

	"github.com/zchee/mitmproxy-go/tlsparse"
)

// buildHello returns a well-formed ClientHello message body (without the
// handshake header) whose total length is bodyLen bytes, with the SNI
// example.com and the ALPN protocols h2 and http/1.1, padded to the length
// with one unknown extension.
func buildHello(t testing.TB, bodyLen int) []byte {
	t.Helper()
	b := []byte{0x03, 0x03}
	b = append(b, make([]byte, 32)...) // random
	b = append(b, 0)                   // session_id length
	b = append(b, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02)
	b = append(b, 1, 0) // compression methods

	sni := []byte("\x00\x0e\x00\x00\x0bexample.com")
	alpn := []byte("\x00\x0c\x02h2\x08http/1.1")
	var exts []byte
	exts = binary.BigEndian.AppendUint16(exts, 0)
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(sni))) //nolint:gosec // G115: short literal.
	exts = append(exts, sni...)
	exts = binary.BigEndian.AppendUint16(exts, 0x10)
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(alpn))) //nolint:gosec // G115: short literal.
	exts = append(exts, alpn...)

	// One unknown (padding) extension brings the message to bodyLen.
	pad := bodyLen - len(b) - 2 - len(exts) - 4
	if pad < 0 {
		t.Fatalf("bodyLen %d is too small for the fixed fields", bodyLen)
	}
	exts = binary.BigEndian.AppendUint16(exts, 0x15)
	exts = binary.BigEndian.AppendUint16(exts, uint16(pad)) //nolint:gosec // G115: bounded by bodyLen.
	exts = append(exts, make([]byte, pad)...)

	b = binary.BigEndian.AppendUint16(b, uint16(len(exts))) //nolint:gosec // G115: bounded by bodyLen.
	b = append(b, exts...)
	if len(b) != bodyLen {
		t.Fatalf("built body is %d bytes, want %d", len(b), bodyLen)
	}
	return b
}

// handshake prepends the 4-byte handshake header declaring len(body).
func handshake(body []byte) []byte {
	n := len(body)
	return append([]byte{0x01, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
}

// inRecords wraps msg in TLS handshake records of at most recordSize bytes.
func inRecords(msg []byte, recordSize int) []byte {
	var out []byte
	for chunk := range slices.Chunk(msg, recordSize) {
		out = append(out, 0x16, 0x03, 0x03)
		out = binary.BigEndian.AppendUint16(out, uint16(len(chunk))) //nolint:gosec // G115: recordSize <= 16384.
		out = append(out, chunk...)
	}
	return out
}

// checkHello asserts the values buildHello encodes.
func checkHello(t *testing.T, ch *tlsparse.ClientHello) {
	t.Helper()
	if got := ch.SNI(); got != "example.com" {
		t.Errorf("SNI() = %q, want %q", got, "example.com")
	}
	want := [][]byte{[]byte("h2"), []byte("http/1.1")}
	if got := ch.ALPNProtocols(); !slices.EqualFunc(got, want, bytes.Equal) {
		t.Errorf("ALPNProtocols() = %q, want %q", got, want)
	}
}

// TestGetClientHelloByteAtATime feeds every prefix of the wire bytes: the
// message must be reported incomplete at every proper prefix and complete,
// byte-identical, only when the last record is whole.
func TestGetClientHelloByteAtATime(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		bodyLen    int
		recordSize int
		minRecords int
	}{
		// More than 4 KiB spread over at least three records.
		"4 KiB hello in three records": {bodyLen: 4800, recordSize: 1700, minRecords: 3},
		// The same message in records of at most 512 bytes.
		"4 KiB hello in 512-byte records": {bodyLen: 4800, recordSize: 512, minRecords: 10},
		// The handshake header itself spread over 1-byte records.
		"one byte per record": {bodyLen: 220, recordSize: 1, minRecords: 220},
		// A declared length whose low byte carries into the third byte
		// when 4 is added: reassembly must wait for all 515 bytes.
		"length low byte 0xff": {bodyLen: 511, recordSize: 600, minRecords: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			msg := handshake(buildHello(t, tt.bodyLen))
			data := inRecords(msg, tt.recordSize)
			if n := (len(msg) + tt.recordSize - 1) / tt.recordSize; n < tt.minRecords {
				t.Fatalf("message spans %d records, want at least %d", n, tt.minRecords)
			}
			for i := range len(data) {
				got, err := tlsparse.GetClientHello(data[:i])
				if got != nil || err != nil {
					t.Fatalf("GetClientHello(data[:%d]) = %x, %v; want nil, nil", i, got, err)
				}
			}
			got, err := tlsparse.GetClientHello(data)
			if err != nil {
				t.Fatalf("GetClientHello: %v", err)
			}
			if !bytes.Equal(got, msg) {
				t.Fatalf("GetClientHello returned %d bytes, want the %d-byte message", len(got), len(msg))
			}
			ch, err := tlsparse.ParseClientHello(data)
			if err != nil {
				t.Fatalf("ParseClientHello: %v", err)
			}
			checkHello(t, ch)
		})
	}
}

// TestGetClientHelloLyingLengths covers declared lengths that do not match
// the bytes on the wire.
func TestGetClientHelloLyingLengths(t *testing.T) {
	t.Parallel()

	msg := handshake(buildHello(t, 300))

	t.Run("record declares more than it holds", func(t *testing.T) {
		t.Parallel()

		data := inRecords(msg, 16384)
		data[3], data[4] = 0xff, 0xff // record length 65535, body unchanged
		got, err := tlsparse.GetClientHello(data)
		if got != nil || err != nil {
			t.Fatalf("GetClientHello = %x, %v; want nil, nil", got, err)
		}
	})

	t.Run("message declares more than the records hold", func(t *testing.T) {
		t.Parallel()

		grown := slices.Clone(msg)
		grown[2] = 0x10 // declared length 0x1000 + the real low bytes
		got, err := tlsparse.GetClientHello(inRecords(grown, 16384))
		if got != nil || err != nil {
			t.Fatalf("GetClientHello = %x, %v; want nil, nil", got, err)
		}
	})

	t.Run("message declares less than the records hold", func(t *testing.T) {
		t.Parallel()

		data := inRecords(append(slices.Clone(msg), 0xaa, 0xbb), 16384)
		got, err := tlsparse.GetClientHello(data)
		if err != nil {
			t.Fatalf("GetClientHello: %v", err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("GetClientHello returned %d bytes, want the declared %d", len(got), len(msg))
		}
	})

	t.Run("garbage record after the complete message", func(t *testing.T) {
		t.Parallel()

		data := append(inRecords(msg, 100), []byte("GET /")...)
		got, err := tlsparse.GetClientHello(data)
		if err != nil {
			t.Fatalf("GetClientHello: %v", err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("GetClientHello returned %d bytes, want the %d-byte message", len(got), len(msg))
		}
	})

	t.Run("garbage record before the message completes", func(t *testing.T) {
		t.Parallel()

		data := append(inRecords(msg[:100], 100), []byte("GET /error")...)
		if _, err := tlsparse.GetClientHello(data); !errors.Is(err, tlsparse.ErrMalformed) {
			t.Fatalf("GetClientHello error = %v, want ErrMalformed", err)
		}
	})
}

// TestGetClientHelloTooLarge: the size cap applies as soon as the declared
// length is known, bytes need not arrive; the largest allowed message passes.
func TestGetClientHelloTooLarge(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		declared int // handshake length field (message size - 4)
		wantErr  error
	}{
		"one over the cap":   {declared: tlsparse.MaxClientHelloSize - 3, wantErr: tlsparse.ErrTooLarge},
		"far over the cap":   {declared: 1 << 23, wantErr: tlsparse.ErrTooLarge},
		"exactly at the cap": {declared: tlsparse.MaxClientHelloSize - 4},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Only the handshake header is on the wire.
			header := []byte{0x01, byte(tt.declared >> 16), byte(tt.declared >> 8), byte(tt.declared)}
			got, err := tlsparse.GetClientHello(inRecords(header, 16384))
			if got != nil || !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetClientHello = %x, %v; want nil, %v", got, err, tt.wantErr)
			}
		})
	}

	t.Run("largest allowed message reassembles", func(t *testing.T) {
		t.Parallel()

		msg := handshake(buildHello(t, tlsparse.MaxClientHelloSize-4))
		got, err := tlsparse.GetClientHello(inRecords(msg, 16384))
		if err != nil {
			t.Fatalf("GetClientHello: %v", err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("GetClientHello returned %d bytes, want %d", len(got), len(msg))
		}
	})
}

// TestGetClientHelloIncompleteAllocation: an oversized declared length must
// not be allocated for before its bytes are there. The wire data declares a
// message near the cap but delivers a few bytes; reassembly must allocate no
// buffer of that size. Not parallel: it reads heap counters.
func TestGetClientHelloIncompleteAllocation(t *testing.T) {
	data := inRecords([]byte{0x01, 0x00, 0xff, 0x00, 0xde, 0xad}, 16384)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 100 {
		got, err := tlsparse.GetClientHello(data)
		if got != nil || err != nil {
			t.Fatalf("GetClientHello = %x, %v; want nil, nil", got, err)
		}
	}
	runtime.ReadMemStats(&after)
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 64<<10 {
		t.Errorf("100 incomplete reassemblies allocated %d bytes; a declared length must not be allocated up front", grown)
	}
}

// TestNewClientHelloTruncated parses the hello truncated at every byte
// offset: no panic, and every result is either a valid hello or an error
// wrapping ErrMalformed.
func TestNewClientHelloTruncated(t *testing.T) {
	t.Parallel()

	body := buildHello(t, 700)
	for i := range len(body) {
		ch, err := tlsparse.NewClientHello(body[:i])
		if err != nil {
			if !errors.Is(err, tlsparse.ErrMalformed) {
				t.Fatalf("NewClientHello(body[:%d]) error %v does not wrap ErrMalformed", i, err)
			}
			continue
		}
		if ch == nil {
			t.Fatalf("NewClientHello(body[:%d]) = nil, nil", i)
		}
	}
}

// TestNewClientHelloQuirks pins the upstream parser's permissive length
// handling that docs/compat.md lists as reproduced on purpose.
func TestNewClientHelloQuirks(t *testing.T) {
	t.Parallel()

	// prefix is everything before the cipher suites.
	prefix := slices.Concat([]byte{0x03, 0x03}, make([]byte, 32), []byte{0})

	tests := map[string]struct {
		body     []byte
		wantErr  bool
		wantSNI  string
		wantCS   []uint16
		wantALPN [][]byte
	}{
		"odd cipher suite length eats the compression length": {
			// Declared cipher length 3: one suite is read, the third byte
			// (0x02) is read as the compression methods' length.
			body:   slices.Concat(prefix, []byte{0x00, 0x03, 0x13, 0x01, 0x02, 0xaa, 0xbb}),
			wantCS: []uint16{0x1301},
		},
		"extensions read past their declared length": {
			// Extensions field declares 0 bytes but an ALPN extension
			// follows: upstream reads to the end of the message.
			body: slices.Concat(prefix, []byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00},
				[]byte{0x00, 0x00},
				[]byte("\x00\x10\x00\x0e\x00\x0c\x02h2\x08http/1.1")),
			wantCS:   []uint16{0x1301},
			wantALPN: [][]byte{[]byte("h2"), []byte("http/1.1")},
		},
		"second server_name extension carries the SNI": {
			// The first server_name extension holds a name of type 1, the
			// second a single valid host_name: upstream returns the second.
			body: slices.Concat(prefix, []byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x1e},
				[]byte("\x00\x00\x00\x08\x00\x06\x01\x00\x03foo"),
				[]byte("\x00\x00\x00\x0e\x00\x0c\x00\x00\x09mitm.test")),
			wantCS:  []uint16{0x1301},
			wantSNI: "mitm.test",
		},
		"two names in one extension give no SNI": {
			body: slices.Concat(prefix, []byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x12},
				[]byte("\x00\x00\x00\x0e\x00\x0c\x00\x00\x03foo\x00\x00\x03bar")),
			wantCS: []uint16{0x1301},
		},
		"empty server_name body is malformed": {
			body: slices.Concat(prefix, []byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x04},
				[]byte("\x00\x00\x00\x00")),
			wantErr: true,
		},
		"server_name with one trailing byte is malformed": {
			body: slices.Concat(prefix, []byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x10},
				[]byte("\x00\x00\x00\x0c\x00\x09\x00\x00\x06ok.one\xff")),
			wantErr: true,
		},
		"alpn with trailing bytes is malformed": {
			body: slices.Concat(prefix, []byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x0a},
				[]byte("\x00\x10\x00\x06\x00\x05\x02h2\xff\xff")),
			wantErr: true,
		},
		"declared cipher length beyond the message is malformed": {
			body:    slices.Concat(prefix, []byte{0xff, 0xff, 0x13, 0x01}),
			wantErr: true,
		},
		"empty message is malformed": {
			body:    nil,
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ch, err := tlsparse.NewClientHello(tt.body)
			if tt.wantErr {
				if !errors.Is(err, tlsparse.ErrMalformed) {
					t.Fatalf("NewClientHello error = %v, want ErrMalformed", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewClientHello: %v", err)
			}
			if got := ch.SNI(); got != tt.wantSNI {
				t.Errorf("SNI() = %q, want %q", got, tt.wantSNI)
			}
			if got := ch.CipherSuites(); !slices.Equal(got, tt.wantCS) {
				t.Errorf("CipherSuites() = %v, want %v", got, tt.wantCS)
			}
			if got := ch.ALPNProtocols(); !slices.EqualFunc(got, tt.wantALPN, bytes.Equal) {
				t.Errorf("ALPNProtocols() = %q, want %q", got, tt.wantALPN)
			}
		})
	}
}

// TestClientHelloImmutable: mutating accessor results and the input slice
// never changes what the hello reports.
func TestClientHelloImmutable(t *testing.T) {
	t.Parallel()

	body := buildHello(t, 300)
	ch, err := tlsparse.NewClientHello(body)
	if err != nil {
		t.Fatalf("NewClientHello: %v", err)
	}
	for i := range body {
		body[i] = 0xff
	}
	raw := ch.RawBytes(false)
	for i := range raw {
		raw[i] = 0
	}
	exts := ch.Extensions()
	for _, ext := range exts {
		for i := range ext.Body {
			ext.Body[i] = 0
		}
	}
	ch.ALPNProtocols()[0][0] = 'x'
	checkHello(t, ch)
}

// TestRawBytesWrappedTooLarge: a body whose synthetic record length would
// not fit 16 bits has no wrapped form.
func TestRawBytesWrappedTooLarge(t *testing.T) {
	t.Parallel()

	ch, err := tlsparse.NewClientHello(buildHello(t, 0xffff-3))
	if err != nil {
		t.Fatalf("NewClientHello: %v", err)
	}
	if got := ch.RawBytes(true); got != nil {
		t.Errorf("RawBytes(true) returned %d bytes, want nil", len(got))
	}
	if got := ch.RawBytes(false); len(got) != 0xffff-3 {
		t.Errorf("RawBytes(false) returned %d bytes, want %d", len(got), 0xffff-3)
	}
}
