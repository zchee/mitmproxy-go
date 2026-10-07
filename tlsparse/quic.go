// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsparse

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
)

const (
	quicVersion1        = 0x00000001
	quicVersion2        = 0x6b3343cf
	maxQUICDatagramSize = 65535
	maxQUICDatagrams    = 256
	maxQUICFragments    = 256
)

// QUICClientHelloParser extracts a TLS ClientHello from QUIC Initial datagrams.
// Its zero value is ready to use. Feed each complete datagram once, in arrival
// order; CRYPTO data may arrive out of order or be retransmitted. The parser
// owns retained bytes and is not safe for concurrent use. It does no I/O.
//
// Datagram size, number of datagrams and disjoint CRYPTO fragments are bounded
// at 65,535 bytes, 256 and 256 respectively; CRYPTO offsets and the complete
// handshake are bounded by MaxClientHelloSize. Sparse offsets never cause
// allocation of missing bytes.
//
// This is the sniffing counterpart of
// py:mitmproxy/proxy/layers/quic/_client_hello_parser.py, not a QUIC endpoint.
// It handles QUIC v1 (RFC 9001) and v2 (RFC 9369) Initial packet protection.
// It does not validate TLS transport parameters or negotiate TLS.
type QUICClientHelloParser struct {
	version   uint32
	dcid      []byte
	hp        cipher.Block
	aead      cipher.AEAD
	iv        []byte
	largestPN uint64
	havePN    bool
	datagrams int
	fragments []quicCryptoFragment
	hello     *ClientHello
	err       error
}

// Feed examines one complete datagram, borrowing it only for the call. It
// returns nil and nil while CRYPTO data is incomplete, an owned immutable
// ClientHello on success, or an error wrapping ErrMalformed or ErrTooLarge.
// A result or error is sticky: subsequent calls return it without reading input.
// Identical overlapping CRYPTO bytes are accepted; conflicting bytes fail.
func (p *QUICClientHelloParser) Feed(datagram []byte) (*ClientHello, error) {
	if p.hello != nil || p.err != nil {
		return p.hello, p.err
	}
	p.err = p.feed(datagram)
	if p.err != nil || p.hello != nil {
		p.fragments = nil
		p.hp, p.aead, p.iv = nil, nil, nil
	}
	return p.hello, p.err
}

// StartsLikeQUICInitial reports whether the first five bytes classify a
// supported-version QUIC Initial long header. It allocates nothing and does
// not check packet lengths, connection IDs or authentication.
func StartsLikeQUICInitial(datagram []byte) bool {
	if len(datagram) < 5 || datagram[0]&0xc0 != 0xc0 {
		return false
	}
	version := binary.BigEndian.Uint32(datagram[1:5])
	return version == quicVersion1 && datagram[0]&0x30 == 0 || version == quicVersion2 && datagram[0]&0x30 == 0x10
}

func (p *QUICClientHelloParser) feed(datagram []byte) error {
	if len(datagram) > maxQUICDatagramSize || p.datagrams == maxQUICDatagrams {
		return ErrTooLarge
	}
	p.datagrams++
	if len(datagram) < 1200 {
		return fmt.Errorf("%w: QUIC Initial datagram is shorter than 1200 bytes", ErrMalformed)
	}
	for len(datagram) > 0 {
		if datagram[0]&0x80 == 0 && p.version != 0 {
			// A coalesced short-header packet consumes the rest of the datagram.
			return nil
		}
		r := parser{buf: datagram}
		first := r.u8()
		v := r.bytes(4)
		if !r.ok() || first&0xc0 != 0xc0 {
			return fmt.Errorf("%w: Packet is not initial one.", ErrMalformed) //nolint:staticcheck // Upstream _client_hello_parser.py:54 diagnostic.
		}
		version := binary.BigEndian.Uint32(v)
		if version != quicVersion1 && version != quicVersion2 || p.version != 0 && p.version != version {
			return fmt.Errorf("%w: unsupported or changed QUIC version", ErrMalformed)
		}
		dcid := r.bytes(int(r.u8()))
		scid := r.bytes(int(r.u8()))
		if !r.ok() || len(dcid) > 20 || len(scid) > 20 {
			return fmt.Errorf("%w: invalid QUIC connection ID", ErrMalformed)
		}
		initial := StartsLikeQUICInitial(datagram)
		if p.version == 0 && !initial {
			return fmt.Errorf("%w: Packet is not initial one.", ErrMalformed) //nolint:staticcheck // Upstream _client_hello_parser.py:54 diagnostic.
		}
		packetType := first & 0x30
		if version == quicVersion1 && packetType == 0x30 || version == quicVersion2 && packetType == 0 {
			return fmt.Errorf("%w: Retry is not a client Initial", ErrMalformed)
		}
		if initial {
			tokenLen, ok := quicVarint(&r)
			if !ok || tokenLen > uint64(r.remaining()) {
				return fmt.Errorf("%w: truncated Initial token", ErrMalformed)
			}
			r.skip(int(tokenLen)) //nolint:gosec // Bounded by available datagram bytes.
		}
		length, ok := quicVarint(&r)
		if !ok || length > uint64(r.remaining()) {
			return fmt.Errorf("%w: truncated QUIC packet", ErrMalformed)
		}
		end := r.off + int(length) //nolint:gosec // Bounded by remaining datagram bytes.
		if initial {
			if p.version == 0 {
				p.version, p.dcid = version, bytes.Clone(dcid)
				var err error
				p.hp, p.aead, p.iv, err = quicInitialKeys(version, dcid)
				if err != nil {
					return err
				}
			} else if !bytes.Equal(p.dcid, dcid) {
				return fmt.Errorf("%w: changed Initial destination connection ID", ErrMalformed)
			}
			if err := p.initial(datagram[:end], r.off); err != nil {
				return err
			}
			if p.hello != nil {
				return nil
			}
		}
		datagram = datagram[end:]
	}
	return nil
}

func quicVarint(r *parser) (uint64, bool) {
	first := r.u8()
	n := 1 << (first >> 6)
	value := uint64(first & 0x3f)
	for range n - 1 {
		value = value<<8 | uint64(r.u8())
	}
	return value, r.ok()
}

func quicInitialKeys(version uint32, dcid []byte) (cipher.Block, cipher.AEAD, []byte, error) {
	// RFC 9001 section 5.2 and RFC 9369 section 3.3.
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	prefix := "quic "
	if version == quicVersion2 {
		salt = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
		prefix = "quicv2 "
	}
	secret, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, nil, nil, err
	}
	clientSecret, err := quicExpandLabel(secret, "client in", 32)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := quicExpandLabel(clientSecret, prefix+"key", 16)
	if err != nil {
		return nil, nil, nil, err
	}
	iv, err := quicExpandLabel(clientSecret, prefix+"iv", 12)
	if err != nil {
		return nil, nil, nil, err
	}
	hpKey, err := quicExpandLabel(clientSecret, prefix+"hp", 16)
	if err != nil {
		return nil, nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	hp, err := aes.NewCipher(hpKey)
	return hp, aead, iv, err
}

func quicExpandLabel(secret []byte, label string, size int) ([]byte, error) {
	label = "tls13 " + label
	info := binary.BigEndian.AppendUint16(nil, uint16(size)) //nolint:gosec // Constant caller sizes 12, 16, 32.
	info = append(info, byte(len(label)))
	info = append(info, label...)
	info = append(info, 0) // Empty HKDF context.
	return hkdf.Expand(sha256.New, secret, string(info), size)
}

func (p *QUICClientHelloParser) initial(packet []byte, pnOffset int) error {
	if len(packet)-pnOffset < 4+aes.BlockSize {
		return fmt.Errorf("%w: truncated header protection sample", ErrMalformed)
	}
	var mask [aes.BlockSize]byte
	p.hp.Encrypt(mask[:], packet[pnOffset+4:pnOffset+4+aes.BlockSize])
	first := packet[0] ^ mask[0]&0x0f
	pnLen := int(first&3) + 1
	if first&0x0c != 0 || len(packet)-pnOffset-pnLen < p.aead.Overhead() {
		return fmt.Errorf("%w: invalid protected Initial header", ErrMalformed)
	}
	header := bytes.Clone(packet[:pnOffset+pnLen])
	header[0] = first
	var truncated uint64
	for i := range pnLen {
		header[pnOffset+i] ^= mask[i+1]
		truncated = truncated<<8 | uint64(header[pnOffset+i])
	}
	expected := uint64(0)
	if p.havePN {
		expected = p.largestPN + 1
	}
	pn := quicPacketNumber(truncated, pnLen, expected)
	var nonce [12]byte
	copy(nonce[:], p.iv)
	for i := range 8 {
		nonce[11-i] ^= byte(pn >> (i * 8))
	}
	payload, err := p.aead.Open(nil, nonce[:], packet[pnOffset+pnLen:], header)
	if err != nil {
		return fmt.Errorf("%w: Invalid ClientHello packet: payload_decrypt_error", ErrMalformed)
	}
	if !p.havePN || pn > p.largestPN {
		p.largestPN, p.havePN = pn, true
	}
	return p.frames(payload)
}

func quicPacketNumber(truncated uint64, size int, expected uint64) uint64 {
	// RFC 9000 appendix A.3; reconstruct around the next expected number.
	window := uint64(1) << (size * 8)
	half := window / 2
	candidate := expected&^(window-1) | truncated
	if candidate+half <= expected && candidate < (1<<62)-window {
		candidate += window
	} else if candidate > expected+half && candidate >= window {
		candidate -= window
	}
	return candidate
}

func (p *QUICClientHelloParser) frames(payload []byte) error {
	r := parser{buf: payload}
	for r.remaining() > 0 {
		typ, ok := quicVarint(&r)
		if !ok {
			return fmt.Errorf("%w: truncated Initial frame type", ErrMalformed)
		}
		switch typ {
		case 0, 1: // PADDING and PING.
		case 2, 3: // ACK and ACK_ECN.
			if !quicSkipACK(&r, typ == 3) {
				return fmt.Errorf("%w: malformed Initial ACK", ErrMalformed)
			}
		case 6: // CRYPTO.
			offset, okOffset := quicVarint(&r)
			length, okLength := quicVarint(&r)
			if !okOffset || !okLength || length > uint64(r.remaining()) {
				return fmt.Errorf("%w: truncated CRYPTO frame", ErrMalformed)
			}
			if offset > MaxClientHelloSize || length > MaxClientHelloSize-offset {
				return ErrTooLarge
			}
			data := r.bytes(int(length))                        //nolint:gosec // Bounded by available payload bytes.
			if err := p.crypto(int(offset), data); err != nil { //nolint:gosec // Offset bounded above.
				return err
			}
		case 0x1c: // CONNECTION_CLOSE in Initial means no ClientHello can complete.
			return fmt.Errorf("%w: QUIC connection closed before ClientHello", ErrMalformed)
		default:
			return fmt.Errorf("%w: frame %#x is not allowed in Initial", ErrMalformed, typ)
		}
	}
	if len(p.fragments) == 0 || p.fragments[0].offset != 0 || len(p.fragments[0].data) < handshakeHeaderLen {
		return nil
	}
	data := p.fragments[0].data
	if data[0] != 1 {
		return fmt.Errorf("%w: Invalid ClientHello data.", ErrMalformed) //nolint:staticcheck // Upstream _client_hello_parser.py:95 diagnostic.
	}
	size := handshakeHeaderLen + int(data[1])<<16 + int(data[2])<<8 + int(data[3])
	if size > MaxClientHelloSize {
		return ErrTooLarge
	}
	if len(data) < size {
		return nil
	}
	var err error
	p.hello, err = NewClientHello(data[handshakeHeaderLen:size])
	return err
}

func quicSkipACK(r *parser, ecn bool) bool {
	largest, ok := quicVarint(r)
	_, delayOK := quicVarint(r)
	count, countOK := quicVarint(r)
	first, firstOK := quicVarint(r)
	if !ok || !delayOK || !countOK || !firstOK || first > largest || count > uint64(r.remaining()/2) {
		return false
	}
	smallest := largest - first
	for range count {
		gap, gapOK := quicVarint(r)
		length, lengthOK := quicVarint(r)
		if !gapOK || !lengthOK || gap+2 > smallest || length > smallest-gap-2 {
			return false
		}
		smallest -= gap + 2 + length
	}
	if ecn {
		for range 3 {
			if _, ok := quicVarint(r); !ok {
				return false
			}
		}
	}
	return true
}

type quicCryptoFragment struct {
	offset int
	data   []byte
}

func (p *QUICClientHelloParser) crypto(offset int, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	end := offset + len(data)
	first := 0
	for first < len(p.fragments) && p.fragments[first].offset+len(p.fragments[first].data) < offset {
		first++
	}
	last := first
	start, stop := offset, end
	for last < len(p.fragments) && p.fragments[last].offset <= stop {
		f := p.fragments[last]
		fend := f.offset + len(f.data)
		lo, hi := max(offset, f.offset), min(end, fend)
		if lo < hi && !bytes.Equal(data[lo-offset:hi-offset], f.data[lo-f.offset:hi-f.offset]) {
			return fmt.Errorf("%w: conflicting CRYPTO data", ErrMalformed)
		}
		start, stop = min(start, f.offset), max(stop, fend)
		last++
	}
	if first == last && len(p.fragments) == maxQUICFragments {
		return ErrTooLarge
	}
	if last == first+1 && start == p.fragments[first].offset && stop == start+len(p.fragments[first].data) {
		return nil // Entire retransmission already present, including checked overlap.
	}
	merged := make([]byte, stop-start)
	for _, f := range p.fragments[first:last] {
		copy(merged[f.offset-start:], f.data)
	}
	copy(merged[offset-start:], data)
	p.fragments = slices.Replace(p.fragments, first, last, quicCryptoFragment{offset: start, data: merged})
	return nil
}
