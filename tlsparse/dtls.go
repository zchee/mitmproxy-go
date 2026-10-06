// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsparse

import (
	"encoding/binary"
	"fmt"
	"iter"

	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

const (
	dtlsRecordHeaderLen    = 13
	dtlsHandshakeHeaderLen = 12
)

// StartsLikeDTLSRecord reports whether d begins with a DTLS handshake content
// type and a DTLS 1.0 or 1.2 record version. It follows mitmproxy's detection
// rule, not the set of versions the proxy can negotiate.
func StartsLikeDTLSRecord(d []byte) bool {
	return len(d) > 2 && d[0] == 0x16 && d[1] == 0xfe && d[2] >= 0xfd && d[2] <= 0xfe
}

// DTLSHandshakeRecordContents iterates complete DTLS handshake record bodies
// in wire order. Bodies borrow data. Incomplete input stops without error;
// non-handshake and empty records yield an error wrapping ErrMalformed.
// Epoch and sequence numbers do not reorder or deduplicate records.
func DTLSHandshakeRecordContents(data []byte) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for offset := 0; ; {
			body, next, err := nextDTLSRecord(data, offset)
			if err != nil {
				yield(nil, err)
				return
			}
			if next < 0 || !yield(body, nil) {
				return
			}
			offset = next
		}
	}
}

func nextDTLSRecord(data []byte, offset int) (body []byte, next int, err error) {
	if len(data)-offset < dtlsRecordHeaderLen {
		return nil, -1, nil
	}
	header := data[offset : offset+dtlsRecordHeaderLen]
	if !StartsLikeDTLSRecord(header) {
		return nil, -1, fmt.Errorf("%w: expected DTLS record, got %s instead", ErrMalformed, pyrepr.Bytes(header))
	}
	size := int(binary.BigEndian.Uint16(header[11:]))
	if size == 0 {
		return nil, -1, fmt.Errorf("%w: record must not be empty", ErrMalformed)
	}
	start := offset + dtlsRecordHeaderLen
	if len(data)-start < size {
		return data[start:], -1, nil
	}
	return data[start : start+size], start + size, nil
}

// GetDTLSClientHello concatenates ordered record bodies and returns the first
// handshake message including its 12-byte header. Incomplete input returns nil
// and nil; malformed records wrap ErrMalformed, and lengths exceeding
// MaxClientHelloSize return ErrTooLarge before allocation.
//
// Like upstream get_dtls_client_hello, the size comes from the first header's
// fragment length. This is not out-of-order handshake fragment reassembly:
// retransmissions and subsequent fragment headers are not removed. Only a
// complete message is allocated, never an untrusted declared length alone.
func GetDTLSClientHello(data []byte) ([]byte, error) {
	var header [dtlsHandshakeHeaderLen]byte
	have, size := 0, -1
	for offset := 0; ; {
		body, next, err := nextDTLSRecord(data, offset)
		if err != nil {
			return nil, err
		}
		if have < dtlsHandshakeHeaderLen {
			n := copy(header[have:], body)
			if have+n == dtlsHandshakeHeaderLen {
				size = (int(header[9])<<16 | int(header[10])<<8 | int(header[11])) + dtlsHandshakeHeaderLen
				if size > MaxClientHelloSize {
					return nil, ErrTooLarge
				}
			}
		}
		if next < 0 {
			return nil, nil
		}
		have += len(body)
		// Upstream requires at least one body byte after the header.
		if size >= 0 && have >= max(size, dtlsHandshakeHeaderLen+1) {
			out := make([]byte, 0, size)
			for b := range DTLSHandshakeRecordContents(data) {
				out = append(out, b[:min(len(b), size-len(out))]...)
				if len(out) == size {
					break
				}
			}
			return out, nil
		}
		offset = next
	}
}

// ParseDTLSClientHello parses the first ClientHello from ordered DTLS records.
// Incomplete input returns nil and nil. Errors wrap ErrMalformed or ErrTooLarge.
// DTLS's cookie field is skipped before parsing ciphers and extensions.
func ParseDTLSClientHello(data []byte) (*ClientHello, error) {
	msg, err := GetDTLSClientHello(data)
	if msg == nil || err != nil {
		return nil, err
	}
	return newClientHello(msg[dtlsHandshakeHeaderLen:], true)
}
