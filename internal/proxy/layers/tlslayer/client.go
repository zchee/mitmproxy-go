// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/tlsparse"
)

func init() {
	layer.Register(hookdata.LayerClientTLS, func(_ *layer.Context, _ hookdata.LayerSpec, child layer.Layer) (layer.Layer, error) {
		return &clientTLS{child: child}, nil
	})
}

// maxHelloDiagnostic bounds the hex dump of a ClientHello that could not be
// parsed, so an attacker cannot size the diagnostic log line.
const maxHelloDiagnostic = 256

// clientTLS terminates TLS with the client, the counterpart of mitmproxy's
// ClientTLSLayer (py:mitmproxy/proxy/layers/tls.py). It collects the whole
// ClientHello handshake message without consuming it, fires tls_clienthello,
// and then either forwards the connection's encrypted contents unmodified (a
// handler set IgnoreConnection, or the hello exceeds a size limit) or
// terminates TLS with the configuration the tls_start_client handlers
// supply, replaying the recorded hello into the handshake.
type clientTLS struct {
	child layer.Layer
}

// Kind implements [layer.Layer].
func (*clientTLS) Kind() hookdata.LayerKind { return hookdata.LayerClientTLS }

// Run implements [layer.Layer].
func (l *clientTLS) Run(ctx context.Context, c *layer.Context) error {
	if err := c.Do(ctx, func(context.Context) error {
		client := c.Data.Client
		if client.TLS {
			// TLS-over-TLS: the outer session between client and proxy is
			// not the interesting one, so the inner session's attributes
			// replace it, as upstream resets them in ClientTLSLayer.
			client.ALPN = nil
			client.ALPNOffers = nil
			client.CertificateList = nil
			client.Cipher = nil
			client.CipherList = nil
			client.MitmCert = nil
			client.SNI = nil
			client.TimestampTLSSetup = nil
			client.TLSVersion = ""
		}
		client.TLS = true
		return nil
	}); err != nil {
		return err
	}
	// Rewind so that bytes consumed before this layer (the next-layer
	// sniff) are part of the hello and of any later replay.
	c.Client.StopRecording()
	hello, err := l.collectClientHello(ctx, c)
	switch {
	case err == nil:
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, layer.ErrRecordSize) || errors.Is(err, tlsparse.ErrTooLarge):
		c.Logger.InfoContext(ctx, fmt.Sprintf("Cannot read the TLS ClientHello within mitmproxy's size limits (%v), forwarding raw TCP.", err))
		return relayRaw(ctx, c)
	case errors.Is(err, tlsparse.ErrMalformed):
		return l.handshakeFailed(ctx, c, &hookdata.TLS{Conn: &c.Data.Client.Connection}, "Cannot parse ClientHello: "+helloDiagnostic(c.Client), slog.LevelWarn)
	default:
		explanation, level := clientHandshakeError(err, clientDest(ctx, c))
		return l.handshakeFailed(ctx, c, &hookdata.TLS{Conn: &c.Data.Client.Connection}, explanation, level)
	}
	data := &hookdata.ClientHello{ClientHello: hello}
	if _, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
		data.Context = c.Data
		client := c.Data.Client
		if sni := hello.SNI(); sni != "" {
			client.SNI = &sni
		} else {
			client.SNI = nil
		}
		client.ALPNOffers = hello.ALPNProtocols()
		return nil
	}, addon.TLSClientHelloHook{Data: data}); err != nil {
		return err
	}
	if data.IgnoreConnection {
		return relayRaw(ctx, c)
	}
	if data.EstablishServerTLSFirst {
		var established bool
		if err := c.Do(ctx, func(context.Context) error {
			established = c.Data.Server.TLSEstablished()
			return nil
		}); err != nil {
			return err
		}
		if !established {
			var reason string
			if _, ok := c.Pool.(*serverTLSPool); !ok {
				reason = "No server TLS available."
			} else if err := startServerTLS(ctx, c); err != nil {
				reason = err.Error()
			}
			if reason != "" {
				c.Logger.InfoContext(ctx, "Unable to establish TLS connection with server ("+reason+"). "+
					"Trying to establish TLS with client anyway. "+
					"If you plan to redirect requests away from this server, "+
					"consider setting `connection_strategy` to `lazy` to suppress early connections.")
			}
		}
	}
	tlsData := &hookdata.TLS{Conn: &c.Data.Client.Connection}
	if _, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
		tlsData.Context = c.Data
		return nil
	}, addon.TLSStartClientHook{Data: tlsData}); err != nil {
		return err
	}
	if tlsData.Config == nil {
		c.Logger.ErrorContext(ctx, "No TLS context was provided, failing connection.")
		return errors.New("tlslayer: no client TLS configuration")
	}
	raw := c.Client
	tc := tls.Server(raw, tlsData.Config)
	if err := tc.HandshakeContext(ctx); err != nil {
		explanation, level := clientHandshakeError(err, clientDest(ctx, c))
		return l.handshakeFailed(ctx, c, tlsData, explanation, level)
	}
	state := tc.ConnectionState()
	if _, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
		client := c.Data.Client
		publishTLS(&client.Connection, &state)
		if len(state.LocalCertificate) > 0 {
			// A resumed session reports no local certificate; the previous
			// value, owned by the tlsconfig addon, is kept then.
			client.MitmCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: state.LocalCertificate[0]})
		}
		return nil
	}, addon.TLSEstablishedClientHook{Data: tlsData}); err != nil {
		return err
	}
	c.Client = c.Record(&tlsConn{Conn: tc, raw: raw})
	child := l.child
	if child == nil {
		var err error
		if child, err = layer.Next(ctx, c); err != nil {
			return err
		}
	}
	return child.Run(ctx, c)
}

// collectClientHello reads the complete ClientHello without consuming it,
// returning early with the context's error when the connection's handler
// shuts down while the client is still sending.
func (l *clientTLS) collectClientHello(ctx context.Context, c *layer.Context) (*tlsparse.ClientHello, error) {
	stop := context.AfterFunc(ctx, func() { _ = c.Client.SetReadDeadline(time.Now()) })
	defer stop()
	hello, err := readClientHello(c.Client)
	if err != nil && ctx.Err() != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, ctx.Err()
	}
	return hello, err
}

// handshakeFailed reports a failed client handshake the way upstream's
// on_handshake_error does: the log line, the connection error, and the
// tls_failed_client hook, in that order.
func (l *clientTLS) handshakeFailed(ctx context.Context, c *layer.Context, data *hookdata.TLS, explanation string, level slog.Level) error {
	c.Logger.Log(ctx, level, "Client TLS handshake failed. "+explanation)
	failure := &handshakeFailure{explanation: explanation}
	_, hookErr := c.Hooks.FireFunc(ctx, func(context.Context) error {
		if data.Context == nil {
			data.Context = c.Data
		}
		c.Data.Client.Error = &failure.explanation
		return nil
	}, addon.TLSFailedClientHook{Data: data})
	return errors.Join(failure, hookErr)
}

// relayRaw forwards the connection's contents unmodified, the
// ignore_connection path of upstream's ClientTLSLayer: a raw TCP relay with
// no flow and no tcp hooks, fed by the rewound recorder so the client sees
// no byte added, changed or lost. Server TLS from a parent layer is
// disabled by handing the relay the undecorated pool, as upstream detaches
// its parent ServerTLSLayer.
func relayRaw(ctx context.Context, c *layer.Context) error {
	relay := *c
	if decorated, ok := relay.Pool.(*serverTLSPool); ok {
		relay.Pool = decorated.inner
	}
	child, err := layer.Build(ctx, &relay, hookdata.LayerStack{{Kind: hookdata.LayerTCP, Ignore: true}})
	if err != nil {
		return err
	}
	return child.Run(ctx, &relay)
}

// startServerTLS establishes TLS with the server before the client
// handshake, so its certificate and ALPN can shape the client's: upstream's
// ClientTLSLayer.start_server_tls. The caller has checked that the pool is
// this package's decorator; an already open raw transport is upgraded in
// place through the recorder that holds its consumed bytes.
func startServerTLS(ctx context.Context, c *layer.Context) error {
	decorated := c.Pool.(*serverTLSPool)
	var metadata *connection.Server
	if err := c.Do(ctx, func(context.Context) error {
		metadata = c.Data.Server
		return nil
	}); err != nil {
		return err
	}
	if c.Server != nil {
		raw := c.Server
		raw.StopRecording()
		upgraded, _, err := decorated.inner.Upgrade(ctx, metadata, func(ctx context.Context, _ layer.Conn, actual *connection.Server) (layer.Conn, error) {
			return decorated.setup(ctx, raw, actual)
		})
		if err != nil {
			return err
		}
		c.Server = c.Record(upgraded)
		return nil
	}
	opened, actual, err := c.Pool.Open(ctx, metadata, layer.OpenOptions{})
	if err != nil {
		return err
	}
	c.Server = c.Record(opened)
	return c.Do(ctx, func(context.Context) error {
		c.Data.Server = actual
		return nil
	})
}

// clientDest names the client's destination for a handshake diagnostic: its
// SNI, or the server address, as upstream's on_handshake_error does.
func clientDest(ctx context.Context, c *layer.Context) string {
	dest := "unknown address"
	_ = c.Do(ctx, func(context.Context) error {
		if sni := c.Data.Client.SNI; sni != nil && *sni != "" {
			dest = *sni
		} else if addr := c.Data.Server.Address; addr != nil {
			dest = addr.String()
		}
		return nil
	})
	return dest
}

// clientHandshakeError explains a failed client handshake and its log level
// as upstream's ClientTLSLayer.on_handshake_error does, translated from
// OpenSSL error identities to their crypto/tls counterparts.
func clientHandshakeError(err error, dest string) (string, slog.Level) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unsupported versions") || strings.Contains(msg, "protocol version"):
		return "Client and mitmproxy cannot agree on a TLS version to use. " +
			"You may need to adjust mitmproxy's tls_version_client_min option.", slog.LevelWarn
	case strings.Contains(msg, "unknown certificate authority") || strings.Contains(msg, "bad certificate") || strings.Contains(msg, "certificate unknown"):
		return fmt.Sprintf("The client does not trust the proxy's certificate for %s (%v)", dest, err), slog.LevelWarn
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) || strings.Contains(msg, "closed pipe") || strings.Contains(msg, "connection reset"):
		return fmt.Sprintf("The client disconnected during the handshake. If this happens consistently for %s, "+
			"this may indicate that the client does not trust the proxy's certificate.", dest), slog.LevelInfo
	default:
		return fmt.Sprintf("The client may not trust the proxy's certificate for %s (%v)", dest, err), slog.LevelWarn
	}
}

// helloDiagnostic hex-dumps the wire bytes of a hello that could not be
// parsed, as upstream's "Cannot parse ClientHello" diagnostic does, bounded
// to [maxHelloDiagnostic] bytes.
func helloDiagnostic(conn layer.Recorder) string {
	buffered := conn.Buffered()
	truncated := buffered > maxHelloDiagnostic
	if truncated {
		buffered = maxHelloDiagnostic
	}
	peeked, err := conn.Peek(buffered)
	dump := hex.EncodeToString(peeked)
	if truncated || err != nil {
		dump += "..."
	}
	return dump
}
