// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"sync"

	dtls "github.com/pion/dtls/v3"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/stateutil"
	"github.com/zchee/mitmproxy-go/internal/tlsnames"
)

// dtlsPackets adapts pion's message-oriented Conn to the packet-layer contract.
// The full read buffer preserves PacketConn's truncation-and-discard semantics;
// pion otherwise rejects a small buffer without returning the truncated bytes.
type dtlsPackets struct {
	*dtls.Conn
	raw     layer.PacketTransport
	readMu  sync.Mutex
	readBuf [layer.MaxUDPPacketBytes]byte
}

var _ layer.PacketTransport = (*dtlsPackets)(nil)

// Context implements [layer.PacketTransport].
func (c *dtlsPackets) Context() context.Context { return c.raw.Context() }

// ReadFrom reads one plaintext datagram, discarding any truncated remainder.
func (c *dtlsPackets) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	n, err := c.Read(c.readBuf[:])
	if err != nil {
		if errors.Is(err, io.EOF) {
			err = errors.Join(net.ErrClosed, err)
		}
		return 0, nil, err
	}
	return copy(p, c.readBuf[:n]), c.RemoteAddr(), nil
}

// WriteTo encrypts one datagram for the session's fixed peer.
func (c *dtlsPackets) WriteTo(p []byte, addr net.Addr) (int, error) {
	peer := c.RemoteAddr()
	if addr != nil && (addr.Network() != peer.Network() || addr.String() != peer.String()) {
		return 0, &net.OpError{Op: "write", Net: "udp", Addr: addr, Err: errors.New("packet peer differs from fixed tuple")}
	}
	if len(p) > layer.MaxUDPPacketBytes {
		return 0, layer.ErrPacketOverflow
	}
	return c.Write(p)
}

// publishDTLS runs under dispatch only after a successful pion handshake.
func publishDTLS(conn *connection.Connection, state *dtls.State) {
	certificates := make([][]byte, 0, len(state.PeerCertificates))
	for _, der := range state.PeerCertificates {
		certificates = append(certificates, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	conn.CertificateList = certificates
	conn.TimestampTLSSetup = new(stateutil.Now())
	conn.ALPN = []byte(state.NegotiatedProtocol)
	cipher := tlsnames.IANA(uint16(state.CipherSuiteID))
	if name, ok := tlsnames.OpenSSL(uint16(state.CipherSuiteID)); ok {
		cipher = name
	}
	conn.Cipher = &cipher
	conn.TLSVersion = connection.DTLSv1_2
}

func failDTLSHandshake(ctx context.Context, c *layer.Context, data *hookdata.TLS, err error) error {
	failure := &handshakeFailure{explanation: err.Error(), err: err}
	var client bool
	if dispatchErr := c.Do(ctx, func(context.Context) error {
		client = data.IsClient()
		return nil
	}); dispatchErr != nil {
		return errors.Join(failure, dispatchErr)
	}
	var hook addon.Hook
	if client {
		c.Logger.WarnContext(ctx, "Client TLS handshake failed. "+failure.explanation)
		hook = addon.TLSFailedClientHook{Data: data}
	} else {
		c.Logger.WarnContext(ctx, "Server TLS handshake failed. "+failure.explanation)
		hook = addon.TLSFailedServerHook{Data: data}
	}
	_, hookErr := c.Hooks.FireFunc(ctx, func(context.Context) error {
		data.Conn.Error = &failure.explanation
		return nil
	}, hook)
	return errors.Join(failure, hookErr)
}
