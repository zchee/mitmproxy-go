// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"strings"
	"sync/atomic"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/stateutil"
	"github.com/zchee/mitmproxy-go/internal/tlsnames"
)

func init() {
	layer.Register(hookdata.LayerServerTLS, func(_ *layer.Context, _ hookdata.LayerSpec, child layer.Layer) (layer.Layer, error) {
		return &serverTLS{child: child}, nil
	})
}

// serverTLS establishes TLS for server connections, the counterpart of
// mitmproxy's ServerTLSLayer (py:mitmproxy/proxy/layers/tls.py). It does
// not open a connection itself: it hands its child a server pool whose
// setup performs the handshake, so TLS starts when the child first needs
// the server, inside the pool's single flight. A transport that is already
// open when the layer starts is upgraded immediately.
type serverTLS struct {
	child layer.Layer
}

// Kind implements [layer.Layer].
func (*serverTLS) Kind() hookdata.LayerKind { return hookdata.LayerServerTLS }

// Run implements [layer.Layer].
func (l *serverTLS) Run(ctx context.Context, c *layer.Context) error {
	pool := &serverTLSPool{inner: c.Pool, c: c}
	derived := *c
	derived.Pool = pool
	if err := c.Do(ctx, func(context.Context) error {
		c.Data.Server.TLS = true
		return nil
	}); err != nil {
		return err
	}
	// An already open transport is upgraded eagerly, unless the direct
	// child terminates TLS with the client: then the hello's SNI and ALPN
	// should shape the server handshake, so the transport is hidden from
	// the child and upgraded when the child first asks the pool for this
	// server, as upstream defers with wait_for_clienthello and begins the
	// handshake only on the child's OpenConnection
	// (py:mitmproxy/proxy/layers/tls.py:472-508), keeping the lazy
	// connection strategy's promise that an upstream connection is deferred
	// as long as possible (py:mitmproxy/addons/proxyserver.py:155-163).
	_, deferToClientHello := l.child.(*clientTLS)
	if derived.Server != nil {
		var metadata *connection.Server
		if err := c.Do(ctx, func(context.Context) error {
			metadata = c.Data.Server
			return nil
		}); err != nil {
			return err
		}
		if deferToClientHello {
			pool.deferred, pool.deferredSrv = derived.Server, metadata
			derived.Server = nil
		} else {
			// The handshake reads through the recorder, not the pool's raw
			// transport, so bytes consumed before the upgrade replay into it.
			raw := derived.Server
			raw.StopRecording()
			upgraded, _, err := c.Pool.Upgrade(ctx, metadata, func(ctx context.Context, _ layer.Conn, actual *connection.Server) (layer.Conn, error) {
				return pool.setup(ctx, raw, actual)
			})
			if err != nil {
				return err
			}
			derived.Server = c.Record(upgraded)
		}
	}
	child := l.child
	if child == nil {
		var err error
		if child, err = layer.Next(ctx, &derived); err != nil {
			return err
		}
	}
	return child.Run(ctx, &derived)
}

// serverTLSPool decorates the connection handler's pool so that every
// connection the child opens, and every raw transport it upgrades, carries
// TLS before the child's own setup sees it. The underlying pool stays
// owned by the handler; the decorator lives only in the derived context.
type serverTLSPool struct {
	inner layer.ServerPool
	c     *layer.Context

	// These identities are fixed before the child starts. Until the
	// upgrade callback finishes, concurrent opens must join Upgrade's
	// single flight rather than bypass it with a new Open.
	deferred     layer.Recorder
	deferredSrv  *connection.Server
	deferredDone atomic.Bool
}

// Open implements [layer.ServerPool]. The connection is marked as destined
// for TLS before the pool sees it, so reuse keys match established TLS
// connections.
func (p *serverTLSPool) Open(ctx context.Context, srv *connection.Server, opts layer.OpenOptions) (layer.Conn, *connection.Server, error) {
	if err := p.markTLS(ctx, srv); err != nil {
		return nil, nil, err
	}
	child := opts.Setup
	if p.deferred != nil && srv == p.deferredSrv && !p.deferredDone.Load() {
		return p.inner.Upgrade(ctx, srv, func(ctx context.Context, _ layer.Conn, actual *connection.Server) (layer.Conn, error) {
			defer p.deferredDone.Store(true)
			// Rewind only inside the pool's single flight: a cancelled
			// waiter must neither consume nor lose the pending recorder.
			p.deferred.StopRecording()
			wrapped, err := p.setup(ctx, p.deferred, actual)
			if err != nil || child == nil {
				return wrapped, err
			}
			return child(ctx, wrapped, actual)
		})
	}
	opts.Setup = func(ctx context.Context, conn layer.Conn, actual *connection.Server) (layer.Conn, error) {
		wrapped, err := p.setup(ctx, conn, actual)
		if err != nil || child == nil {
			return wrapped, err
		}
		return child(ctx, wrapped, actual)
	}
	return p.inner.Open(ctx, srv, opts)
}

// Upgrade implements [layer.ServerPool].
func (p *serverTLSPool) Upgrade(ctx context.Context, srv *connection.Server, setup func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error)) (layer.Conn, *connection.Server, error) {
	if err := p.markTLS(ctx, srv); err != nil {
		return nil, nil, err
	}
	return p.inner.Upgrade(ctx, srv, func(ctx context.Context, conn layer.Conn, actual *connection.Server) (layer.Conn, error) {
		wrapped, err := p.setup(ctx, conn, actual)
		if err != nil || setup == nil {
			return wrapped, err
		}
		return setup(ctx, wrapped, actual)
	})
}

// Lookup implements [layer.ServerPool].
func (p *serverTLSPool) Lookup(srv *connection.Server) (layer.Conn, bool) { return p.inner.Lookup(srv) }

// markTLS records that TLS will eventually be established with srv, before
// the pool keys or dials the connection.
func (p *serverTLSPool) markTLS(ctx context.Context, srv *connection.Server) error {
	return p.c.Do(ctx, func(context.Context) error {
		srv.TLS = true
		return nil
	})
}

// setup performs the server-side TLS handshake over an open transport. It
// runs inside the pool's single flight, outside the dispatch lock. The
// hook data belongs to the layer: a tls_start_server handler supplies
// Config during dispatch and must not retain the data afterwards.
func (p *serverTLSPool) setup(ctx context.Context, conn layer.Conn, srv *connection.Server) (layer.Conn, error) {
	data := &hookdata.TLS{Conn: &srv.Connection}
	if _, err := p.c.Hooks.FireFunc(ctx, func(context.Context) error {
		data.Context = p.hookContext(srv)
		return nil
	}, addon.TLSStartServerHook{Data: data}); err != nil {
		return nil, err
	}
	if data.Config == nil {
		p.c.Logger.ErrorContext(ctx, "No TLS context was provided, failing connection.")
		return nil, errors.New("tlslayer: no server TLS configuration")
	}
	tc := tls.Client(conn, data.Config)
	if err := tc.HandshakeContext(ctx); err != nil {
		failure := &handshakeFailure{explanation: serverHandshakeError(err), err: err}
		p.c.Logger.WarnContext(ctx, "Server TLS handshake failed. "+failure.explanation)
		_, hookErr := p.c.Hooks.FireFunc(ctx, func(context.Context) error {
			srv.Error = &failure.explanation
			return nil
		}, addon.TLSFailedServerHook{Data: data})
		return nil, errors.Join(failure, hookErr)
	}
	state := tc.ConnectionState()
	if _, err := p.c.Hooks.FireFunc(ctx, func(context.Context) error {
		publishTLS(&srv.Connection, &state)
		return nil
	}, addon.TLSEstablishedServerHook{Data: data}); err != nil {
		return nil, err
	}
	return &tlsConn{Conn: tc, raw: conn, srv: srv, logger: p.c.Logger}, nil
}

// hookContext returns the hook-visible context for a handshake with srv:
// the connection's own context, or, for a connection to another server
// than the context's, a copy with Server rebound to srv so TLS hook
// handlers see the server the handshake is about. It runs under the
// dispatch lock.
func (p *serverTLSPool) hookContext(srv *connection.Server) *hookdata.Context {
	if srv == p.c.Data.Server {
		return p.c.Data
	}
	derived := *p.c.Data
	derived.Server = srv
	return &derived
}

// handshakeFailure carries the explanation upstream presents for a failed
// handshake while preserving the underlying error chain.
type handshakeFailure struct {
	explanation string
	err         error
}

// Error implements the error interface.
func (e *handshakeFailure) Error() string { return e.explanation }

// Unwrap makes the original handshake error available to [errors.Is].
func (e *handshakeFailure) Unwrap() error { return e.err }

// serverHandshakeError explains a server handshake error the way upstream
// does (py:mitmproxy/proxy/layers/tls.py), translated from OpenSSL error
// identities to their crypto/tls counterparts; an error without a friendly
// explanation keeps its own text.
func serverHandshakeError(err error) string {
	if record, ok := errors.AsType[tls.RecordHeaderError](err); ok && asciiHeader(record.RecordHeader[:4]) {
		return "The remote server does not speak TLS."
	}
	if verify, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
		return "Certificate verify failed: " + verify.Err.Error()
	}
	if strings.Contains(err.Error(), "protocol version") {
		return "The remote server and mitmproxy cannot agree on a TLS version to use. " +
			"You may need to adjust mitmproxy's tls_version_server_min option."
	}
	return err.Error()
}

// asciiHeader reports whether the peer's first bytes are ASCII, the test
// upstream uses to tell a plaintext response from TLS line noise.
func asciiHeader(header []byte) bool {
	for _, b := range header {
		if b >= 0x80 {
			return false
		}
	}
	return true
}

// publishTLS records a completed handshake on conn as upstream does after
// do_handshake: certificates, timestamp, ALPN (non-nil even when nothing
// was negotiated), cipher and version. It runs under the dispatch lock.
func publishTLS(conn *connection.Connection, state *tls.ConnectionState) {
	certs := make([][]byte, 0, len(state.PeerCertificates))
	for _, cert := range state.PeerCertificates {
		certs = append(certs, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}
	conn.CertificateList = certs
	conn.TimestampTLSSetup = new(stateutil.Now())
	conn.ALPN = []byte(state.NegotiatedProtocol)
	cipher := tlsnames.IANA(state.CipherSuite)
	if name, ok := tlsnames.OpenSSL(state.CipherSuite); ok {
		cipher = name
	}
	conn.Cipher = &cipher
	conn.TLSVersion = versionName(state.Version)
}

// versionName names a negotiated protocol version as OpenSSL's
// SSL_get_version does, the spelling [connection.TLSVersion] requires.
func versionName(version uint16) connection.TLSVersion {
	switch version {
	case tls.VersionTLS10:
		return connection.TLSv1
	case tls.VersionTLS11:
		return connection.TLSv1_1
	case tls.VersionTLS12:
		return connection.TLSv1_2
	case tls.VersionTLS13:
		return connection.TLSv1_3
	}
	return ""
}
