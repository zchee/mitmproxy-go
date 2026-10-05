// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsparse

import (
	"encoding/binary"
	"errors"
	"fmt"
	"iter"

	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

// MaxClientHelloSize is the largest handshake message, its 4-byte header
// included, that GetClientHello and ParseClientHello reassemble. A client
// that declares a longer message gets ErrTooLarge as soon as the length is
// known, so the proxy never buffers more than this while it waits for a
// ClientHello. mitmproxy has no such limit.
const MaxClientHelloSize = 64 << 10

const (
	recordHeaderLen    = 5
	handshakeHeaderLen = 4
	// maxWrappedBodySize is the largest ClientHello body whose record
	// length fits the synthetic record header's 16-bit length field:
	// 65,535 minus the handshake header.
	maxWrappedBodySize = 0xffff - handshakeHeaderLen
)

// ErrMalformed is wrapped by every error that reports bytes which are not a
// well-formed ClientHello or TLS handshake record; mitmproxy raises
// ValueError for the same inputs.
var ErrMalformed = errors.New("tlsparse: malformed ClientHello")

// ErrTooLarge is returned by GetClientHello and ParseClientHello when the
// handshake message declares a length that exceeds MaxClientHelloSize.
var ErrTooLarge = fmt.Errorf("tlsparse: ClientHello exceeds %d bytes", MaxClientHelloSize)

// StartsLikeTLSRecord reports whether d could be the start of a TLS record
// that carries a handshake message: a handshake content type followed by a
// record version from SSL 3.0 to TLS 1.2, the versions every TLS client
// up to TLS 1.3 sends. Fewer than three bytes never count as a TLS record
// (py:mitmproxy/net/tls.py starts_like_tls_record).
func StartsLikeTLSRecord(d []byte) bool {
	return len(d) > 2 && d[0] == 0x16 && d[1] == 0x03 && d[2] <= 0x03
}

// HandshakeRecordContents returns an iterator over the bodies of the
// complete TLS handshake records at the start of data
// (py:mitmproxy/proxy/layers/tls.py handshake_record_contents).
//
// Each body is yielded with a nil error; it is a subslice of data, not a
// copy. The iteration stops without an error at the first record whose
// header or body is incomplete. A record that is not a handshake record, or
// that is empty, ends the iteration with one nil body and an error wrapping
// ErrMalformed; as in mitmproxy, records after the ones a caller needs are
// only checked if the caller keeps iterating.
func HandshakeRecordContents(data []byte) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for offset := 0; ; {
			body, next, err := nextRecord(data, offset)
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

// nextRecord reads the record at offset. It returns the record body and the
// offset of the record after it, or next < 0 when the record is incomplete.
// An incomplete body is returned as far as available, so its handshake
// length can be checked before the rest of the record arrives.
func nextRecord(data []byte, offset int) (body []byte, next int, err error) {
	if len(data)-offset < recordHeaderLen {
		return nil, -1, nil
	}
	header := data[offset : offset+recordHeaderLen]
	if !StartsLikeTLSRecord(header) {
		return nil, -1, fmt.Errorf("%w: expected TLS record, got %s instead", ErrMalformed, pyrepr.Bytes(header))
	}
	size := int(binary.BigEndian.Uint16(header[3:]))
	if size == 0 {
		return nil, -1, fmt.Errorf("%w: record must not be empty", ErrMalformed)
	}
	start := offset + recordHeaderLen
	if len(data)-start < size {
		return data[start:], -1, nil
	}
	return data[start : start+size], start + size, nil
}

// GetClientHello reassembles the first handshake message from the TLS
// records at the start of data and returns it with its 4-byte handshake
// header, without the record headers
// (py:mitmproxy/proxy/layers/tls.py get_client_hello).
//
// GetClientHello returns nil and a nil error when data does not hold the
// whole message yet; the caller retries with more data. It returns an error
// wrapping ErrMalformed for a record that is not a handshake record or is
// empty, and ErrTooLarge as soon as the message declares a length beyond
// MaxClientHelloSize. As in mitmproxy, the handshake message type is not
// checked; ParseClientHello rejects what does not parse as a ClientHello.
//
// The returned slice is newly allocated, and only once all of its bytes are
// in data, so a declared length never causes an allocation by itself.
func GetClientHello(data []byte) ([]byte, error) {
	// The first pass finds the declared length, which may itself be spread
	// over several records, and checks that all bytes are there.
	var (
		have   int
		header [handshakeHeaderLen]byte
		size   = -1
		count  int
	)
	for offset := 0; ; {
		body, next, err := nextRecord(data, offset)
		if err != nil {
			return nil, err
		}
		count++
		if size < 0 {
			n := copy(header[have:], body)
			if have+n == handshakeHeaderLen {
				size = (int(header[1])<<16 | int(header[2])<<8 | int(header[3])) + handshakeHeaderLen
				if size > MaxClientHelloSize {
					return nil, ErrTooLarge
				}
			}
		}
		if next < 0 {
			return nil, nil
		}
		have += len(body)
		if size >= 0 && have >= size {
			return assemble(data, count, size), nil
		}
		offset = next
	}
}

// assemble copies the first size bytes of the bodies of the first count
// records of data, which GetClientHello has checked, into a new slice.
func assemble(data []byte, count, size int) []byte {
	out := make([]byte, 0, size)
	for body := range HandshakeRecordContents(data) {
		out = append(out, body[:min(len(body), size-len(out))]...)
		if count--; count == 0 {
			break
		}
	}
	return out
}

// ParseClientHello reassembles the first handshake message from the TLS
// records at the start of data, as GetClientHello does, and parses it as a
// ClientHello (py:mitmproxy/proxy/layers/tls.py parse_client_hello).
//
// ParseClientHello returns nil and a nil error when data does not hold the
// whole message yet. It returns an error wrapping ErrMalformed when the
// records or the message are malformed, and ErrTooLarge when the message
// declares a length beyond MaxClientHelloSize.
func ParseClientHello(data []byte) (*ClientHello, error) {
	msg, err := GetClientHello(data)
	if msg == nil || err != nil {
		return nil, err
	}
	return NewClientHello(msg[handshakeHeaderLen:])
}
