// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsparse

import "encoding/binary"

// ClientHelloParser incrementally parses the first ClientHello in TLS records.
// Its zero value is ready to use. Input must be an immutable, growing prefix
// belonging to one stream; the parser is not safe for concurrent use.
// Each record header is examined once, and the message is copied only after
// all its records have arrived, without allocating from an untrusted length.
type ClientHelloParser struct {
	offset  int
	end     int
	records int
	have    int
	header  [handshakeHeaderLen]byte
	size    int
	need    int
	hello   *ClientHello
	err     error
}

// Parse reads the immutable, growing TLS record prefix in data. It returns nil
// and nil while incomplete, ErrTooLarge as soon as an oversized handshake
// length is available, or an error wrapping ErrMalformed for invalid input.
// A completed result or error is retained and returned on subsequent calls.
func (p *ClientHelloParser) Parse(data []byte) (*ClientHello, error) {
	if p.hello != nil || p.err != nil || len(data) < p.need {
		return p.hello, p.err
	}
	for {
		if p.end == 0 {
			if len(data)-p.offset < recordHeaderLen {
				p.need = p.offset + recordHeaderLen
				return nil, nil
			}
			if _, _, err := nextRecord(data, p.offset); err != nil {
				p.err = err
				return nil, err
			}
			p.end = p.offset + recordHeaderLen + int(binary.BigEndian.Uint16(data[p.offset+3:p.offset+5]))
			p.records++
		}
		start := p.offset + recordHeaderLen
		p.need = p.end
		if p.size == 0 {
			n := copy(p.header[p.have:], data[start:min(len(data), p.end)])
			if p.have+n == handshakeHeaderLen {
				p.size = (int(p.header[1])<<16 | int(p.header[2])<<8 | int(p.header[3])) + handshakeHeaderLen
				if p.size > MaxClientHelloSize {
					p.err = ErrTooLarge
					return nil, p.err
				}
			} else {
				p.need = min(p.end, start+handshakeHeaderLen-p.have)
			}
		}
		if len(data) < p.end {
			return nil, nil
		}
		p.have += p.end - start
		p.offset = p.end
		p.end = 0
		if p.size != 0 && p.have >= p.size {
			message := assemble(data, p.records, p.size)
			p.hello, p.err = NewClientHello(message[handshakeHeaderLen:])
			return p.hello, p.err
		}
	}
}
