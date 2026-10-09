// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net"
	"strings"
	"sync"
	"testing"

	quicgo "github.com/quic-go/quic-go"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// This fixture retains synthetic TLS secrets only in memory. It replaces one
// authenticated application packet with an unknown transport frame (RFC 9000
// section 12.4); the receiver, not a synthetic tracer event, generates the error.
type invalidQUICFramePeer struct {
	net.PacketConn
	mu      sync.Mutex
	secrets bytes.Buffer
	armed   bool
	suite   uint16
	sent    chan error
}

func (p *invalidQUICFramePeer) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.secrets.Write(data)
}

func (p *invalidQUICFramePeer) WriteTo(data []byte, addr net.Addr) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.armed || len(data) == 0 || data[0]&0x80 != 0 {
		return p.PacketConn.WriteTo(data, addr)
	}
	p.armed = false
	packet, err := p.invalidFrame(data)
	if err != nil {
		p.sent <- err
		return 0, err
	}
	n, err := p.PacketConn.WriteTo(packet, addr)
	p.sent <- err
	return n, err
}

func (p *invalidQUICFramePeer) invalidFrame(packet []byte) ([]byte, error) {
	var secret []byte
	for line := range strings.SplitSeq(p.secrets.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "SERVER_TRAFFIC_SECRET_0" {
			var err error
			secret, err = hex.DecodeString(fields[2])
			if err != nil {
				return nil, err
			}
			break
		}
	}
	if secret == nil {
		return nil, errors.New("missing synthetic application traffic secret")
	}
	hashFunc, keyLen := sha256.New, 16
	if p.suite == tls.TLS_AES_256_GCM_SHA384 {
		hashFunc, keyLen = sha512.New384, 32
	}
	if p.suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		keyLen = 32
	}
	key, err := quicFramePeerKey(hashFunc, secret, "quic key", keyLen)
	if err != nil {
		return nil, err
	}
	iv, err := quicFramePeerKey(hashFunc, secret, "quic iv", 12)
	if err != nil {
		return nil, err
	}
	hp, err := quicFramePeerKey(hashFunc, secret, "quic hp", keyLen)
	if err != nil {
		return nil, err
	}
	var aead cipher.AEAD
	var headerBlock cipher.Block
	switch p.suite {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		headerBlock, err = aes.NewCipher(hp)
		if err != nil {
			return nil, err
		}
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		aead, err = chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported fixture cipher suite %#x", p.suite)
	}
	// The short header omits the CID length. Try the bounded RFC CID range,
	// accepting a candidate only after AEAD authentication succeeds.
	for cidLen := range 21 {
		pnOffset := 1 + cidLen
		if len(packet) < pnOffset+4+16 {
			continue
		}
		var mask [16]byte
		sample := packet[pnOffset+4 : pnOffset+4+16]
		if headerBlock != nil {
			headerBlock.Encrypt(mask[:], sample)
		} else {
			stream, err := chacha20.NewUnauthenticatedCipher(hp, sample[4:])
			if err != nil {
				return nil, err
			}
			stream.SetCounter(binary.LittleEndian.Uint32(sample[:4]))
			stream.XORKeyStream(mask[:5], mask[:5])
		}
		first := packet[0] ^ (mask[0] & 0x1f)
		pnLen := int(first&3) + 1
		header := bytes.Clone(packet[:pnOffset+pnLen])
		header[0] = first
		var pn uint64
		for i := range pnLen {
			header[pnOffset+i] ^= mask[i+1]
			pn = pn<<8 | uint64(header[pnOffset+i])
		}
		nonce := bytes.Clone(iv)
		for i := range 8 {
			nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
		}
		plain, err := aead.Open(nil, nonce, packet[len(header):], header)
		if err != nil {
			continue
		}
		clear(plain)
		plain[0] = 0x1f // Unassigned frame type; the remaining bytes are PADDING.
		result := aead.Seal(header, nonce, plain, header)
		sample = result[pnOffset+4 : pnOffset+4+16]
		if headerBlock != nil {
			headerBlock.Encrypt(mask[:], sample)
		} else {
			stream, err := chacha20.NewUnauthenticatedCipher(hp, sample[4:])
			if err != nil {
				return nil, err
			}
			stream.SetCounter(binary.LittleEndian.Uint32(sample[:4]))
			clear(mask[:])
			stream.XORKeyStream(mask[:5], mask[:5])
		}
		result[0] ^= mask[0] & 0x1f
		for i := range pnLen {
			result[pnOffset+i] ^= mask[i+1]
		}
		return result, nil
	}
	return nil, errors.New("fixture application packet did not authenticate")
}

func quicFramePeerKey(hashFunc func() hash.Hash, secret []byte, label string, length int) ([]byte, error) {
	label = "tls13 " + label
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(len(label)))
	info = append(info, label...)
	info = append(info, 0)
	return hkdf.Expand(hashFunc, secret, string(info), length)
}

type transportCloseConsumer struct{ returned chan error }

func (c *transportCloseConsumer) RunQUIC(ctx context.Context, config *layer.Context, client, server *quicgo.Conn) error {
	return relayQUIC(ctx, config, client, server)
}

func (c *transportCloseConsumer) rawReturned(err error) { c.returned <- err }

func TestQUICPeerTransportErrorCleanup(t *testing.T) {
	// Certification: transport codes are not mapped to application codes.
	// py:mitmproxy/proxy/layers/quic/_raw_layers.py:290-302 forwards them;
	// quic-go's public CloseWithError emits only application CONNECTION_CLOSE.
	peer := &invalidQUICFramePeer{sent: make(chan error, 1)}
	consumer := &transportCloseConsumer{returned: make(chan error, 1)}
	observer := &wireObserver{
		ended: make(chan *flow.TCPFlow, 1), consumer: consumer,
		originKeyLog:  peer,
		originPackets: func(conn net.PacketConn) net.PacketConn { peer.PacketConn = conn; return peer },
	}
	session := newWireSession(t, nil, observer)
	wireAwaitServerEstablished(t, observer)
	stream, err := session.client.OpenStreamSync(session.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("READY")); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	origin, err := session.origin.AcceptStream(session.ctx)
	if err != nil {
		t.Fatal(err)
	}
	peer.mu.Lock()
	peer.suite = session.origin.ConnectionState().TLS.CipherSuite
	peer.armed = true
	peer.mu.Unlock()
	if _, err := origin.Write([]byte("invalid frame")); err != nil {
		t.Fatal(err)
	}
	if err := wireAwait(t, peer.sent); err != nil {
		t.Fatal(err)
	}
	cause := wireAwait(t, consumer.returned)
	failure, ok := errors.AsType[*quicgo.TransportError](cause)
	if !ok || failure.ErrorCode != 0x7 || failure.FrameType != 0x1f || failure.Remote {
		t.Fatalf("original typed transport diagnostic = %T: %v", cause, cause)
	}
	wireAwait(t, session.client.Context().Done())
	cleanup, ok := errors.AsType[*quicgo.ApplicationError](context.Cause(session.client.Context()))
	if !ok || !cleanup.Remote || cleanup.ErrorCode != 0 || cleanup.ErrorMessage != "" {
		t.Fatalf("opposite peer cleanup close = %v", context.Cause(session.client.Context()))
	}
}
