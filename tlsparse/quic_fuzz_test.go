// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsparse

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func FuzzQUICClientHello(f *testing.F) {
	for _, name := range []string{"client_hello", "rfc9001_client_initial", "rfc9369_client_initial"} {
		data := quicVector(f, name)
		seed := binary.BigEndian.AppendUint16(nil, uint16(len(data))) //nolint:gosec // Fixed fixture lengths <=65535.
		f.Add(append(seed, data...))
	}
	first, second := quicVector(f, "fragmented_client_hello1"), quicVector(f, "fragmented_client_hello2")
	seed := binary.BigEndian.AppendUint16(nil, uint16(len(first))) //nolint:gosec // Fixed fixture length <=65535.
	seed = append(seed, first...)
	seed = binary.BigEndian.AppendUint16(seed, uint16(len(second))) //nolint:gosec // Fixed fixture length <=65535.
	f.Add(append(seed, second...))
	f.Add([]byte{0, 1, 0xc0})
	f.Add(quicCryptoFrame(MaxClientHelloSize-1, []byte{42}))
	f.Add(quicCryptoFrame(0, []byte{1, 1, 0, 0}))
	f.Add(appendQUICInt([]byte{6, 0}, 1<<40))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		// Mutation cannot normally pass AEAD authentication. Exercise the
		// decrypted frame parser as well, without bypassing Feed's wire seeds.
		if len(data) <= maxQUICDatagramSize {
			var frames QUICClientHelloParser
			_ = frames.frames(data)
			retained := 0
			for _, fragment := range frames.fragments {
				retained += len(fragment.data)
			}
			if retained > MaxClientHelloSize || len(frames.fragments) > maxQUICFragments {
				t.Fatal("decrypted frame retention exceeds bounds")
			}
		}
		var p QUICClientHelloParser
		for len(data) > 0 {
			if len(data) < 2 {
				return
			}
			size := min(int(binary.BigEndian.Uint16(data)), len(data)-2)
			packet := bytes.Clone(data[2 : 2+size])
			before := bytes.Clone(packet)
			hello, err := p.Feed(packet)
			if !bytes.Equal(before, packet) {
				t.Fatal("Feed mutated input datagram")
			}
			retained := 0
			for i, fragment := range p.fragments {
				retained += len(fragment.data)
				if fragment.offset < 0 || fragment.offset+len(fragment.data) > MaxClientHelloSize {
					t.Fatal("fragment offset exceeds bound")
				}
				if i > 0 && p.fragments[i-1].offset+len(p.fragments[i-1].data) >= fragment.offset {
					t.Fatal("fragments overlap or contiguous fragments were not merged")
				}
			}
			if retained > MaxClientHelloSize || len(p.fragments) > maxQUICFragments || p.datagrams > maxQUICDatagrams {
				t.Fatal("parser retention exceeds bounds")
			}
			if hello != nil || err != nil {
				if again, againErr := p.Feed(nil); again != hello || againErr != err {
					t.Fatal("completed result changed")
				}
				return
			}
			clear(packet)
			data = data[2+size:]
		}
	})
}
