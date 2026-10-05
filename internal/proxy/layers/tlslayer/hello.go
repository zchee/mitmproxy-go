// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package tlslayer intercepts TLS connections using the configuration supplied
// by TLS hook handlers. Hook data belongs to the layer: handlers may change it
// during dispatch, but must not retain it and mutate it after returning.
package tlslayer

import (
	"encoding/binary"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/tlsparse"
)

// readClientHello leaves original record bytes, including lookahead, in conn.
// The recorder bounds wire bytes independently of tlsparse's 64 KiB handshake
// cap. The handler supplies a recorder with a 128 KiB wire bound. Records are
// visited once; parsing the accumulated hello on every byte would be quadratic.
func readClientHello(conn layer.Recorder) (*tlsparse.ClientHello, error) {
	var header [4]byte
	var headerBytes, payloadBytes, wireBytes int
	messageSize := -1
	for {
		wire, err := conn.Peek(wireBytes + 5)
		if err != nil {
			return nil, err
		}
		record := wire[wireBytes:]
		recordSize := int(binary.BigEndian.Uint16(record[3:5]))
		if !tlsparse.StartsLikeTLSRecord(record) || recordSize == 0 {
			return tlsparse.ParseClientHello(record)
		}
		if headerBytes < len(header) {
			n := min(recordSize, len(header)-headerBytes)
			wire, err = conn.Peek(wireBytes + 5 + n)
			if err != nil {
				return nil, err
			}
			headerBytes += copy(header[headerBytes:], wire[wireBytes+5:])
			if headerBytes == len(header) {
				messageSize = 4 + (int(header[1])<<16 | int(header[2])<<8 | int(header[3]))
				if messageSize > tlsparse.MaxClientHelloSize {
					return nil, tlsparse.ErrTooLarge
				}
			}
		}
		wireBytes += 5 + recordSize
		wire, err = conn.Peek(wireBytes)
		if err != nil {
			return nil, err
		}
		payloadBytes += recordSize
		if messageSize >= 0 && payloadBytes >= messageSize {
			return tlsparse.ParseClientHello(wire)
		}
	}
}
