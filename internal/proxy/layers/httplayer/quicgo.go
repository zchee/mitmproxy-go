// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h3"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layers/tlslayer"
)

// http3DrainTimeout bounds exchange draining after a physical connection close.
// The raw owner cancels the consumer context on that close, so a later external
// cancellation is unobservable and may cost this additional drain interval.
const http3DrainTimeout = 3 * time.Second

// http3RetainedOrigins bounds per-client destination state; upstream has no
// equivalent table. Active, establishing and caller-owned origins are protected.
const http3RetainedOrigins = 100

// RunQUIC borrows established QUIC connections and serves independent HTTP/3
// exchanges. It joins all stream owners before returning and closes connections
// only for a protocol abort; their normal lifetime remains with the caller.
func (l *httpLayer) RunQUIC(ctx context.Context, c *layer.Context, client, server *quic.Conn) (result error) {
	if c == nil || c.Data == nil || c.Do == nil || c.Hooks == nil || client == nil || server == nil {
		return errors.New("httplayer: HTTP/3 requires established QUIC endpoints and dispatch")
	}
	var downstream, upstream layer.EndpointDescriptor
	var enabled, validate, normalize bool
	if err := c.Do(ctx, func(context.Context) error {
		if c.Data.Client == nil || c.Data.Server == nil {
			return errors.New("httplayer: HTTP/3 connection metadata is required")
		}
		enabled, validate, normalize = true, true, true
		if opts := c.Data.Options; opts != nil {
			if opts.Has("http3") {
				enabled = opts.Bool("http3")
			}
			if opts.Has("validate_inbound_headers") {
				validate = opts.Bool("validate_inbound_headers")
			}
			if opts.Has("normalize_outbound_headers") {
				normalize = opts.Bool("normalize_outbound_headers")
			}
		}
		c.Data.Client.TLSVersion, c.Data.Server.TLSVersion = connection.QUICv1, connection.QUICv1
		c.Data.Client.ALPN, c.Data.Server.ALPN = []byte("h3"), []byte("h3")
		c.Data.Client.TLS, c.Data.Server.TLS = true, true
		c.Data.Client.TransportProtocol, c.Data.Server.TransportProtocol = connection.UDP, connection.UDP
		if srv := c.Data.Server; srv.SNI == nil && srv.Address != nil {
			srv.SNI = new(srv.Address.Host)
			if c.Data.Client.SNI != nil {
				srv.SNI = new(*c.Data.Client.SNI)
			}
		}
		downstream = layer.EndpointDescriptor{Identity: layer.EndpointID(c.Data.Client.ID), ConnectionID: c.Data.Client.ID, Protocol: "h3", FromClient: true}
		upstream = layer.EndpointDescriptor{Identity: layer.EndpointID(c.Data.Server.ID), ConnectionID: c.Data.Server.ID, Protocol: "h3"}
		return nil
	}); err != nil {
		return err
	}
	if !enabled {
		_ = client.CloseWithError(quic.ApplicationErrorCode(h3.ErrCodeVersionFallback), "")
		_ = server.CloseWithError(quic.ApplicationErrorCode(h3.ErrCodeVersionFallback), "")
		return &h3.ConnectionError{Code: h3.ErrCodeVersionFallback, Message: "HTTP/3 is disabled"}
	}
	incoming, err := h3.New(client, h3.Config{Descriptor: downstream, ValidateInboundHeaders: validate, Logger: c.Logger})
	if err != nil {
		return err
	}
	outgoing, err := h3.New(server, h3.Config{Descriptor: upstream, Client: true, ValidateInboundHeaders: validate, Logger: c.Logger})
	if err != nil {
		return err
	}
	lifecycle := ctx
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	exchangeCtx, cancelExchanges := context.WithCancel(context.WithoutCancel(lifecycle))
	var exchanges sync.WaitGroup
	endpoints := newHTTPOrigins(ctx)
	defer endpoints.stop()
	if err := c.Do(ctx, func(context.Context) error {
		if c.Data.Server.Address != nil {
			endpoints.quic.borrow(c.Data.Server, server, outgoing)
		}
		return nil
	}); err != nil {
		cancelExchanges()
		cancel()
		return err
	}
	var workers sync.WaitGroup
	defer func() {
		// Publish an abort before cancellation can reset critical streams and
		// make the peer report a different connection failure.
		if failure, ok := errors.AsType[*h3.ConnectionError](result); ok && failure.Code != h3.ErrCodeNoError && failure.Code != 0 {
			_ = client.CloseWithError(quic.ApplicationErrorCode(failure.Code), "")
			_ = server.CloseWithError(quic.ApplicationErrorCode(failure.Code), "")
		}
		if client.Context().Err() != nil || server.Context().Err() != nil {
			clock := c.Clock
			if clock == nil {
				clock = layer.WallClock
			}
			stop := clock.AfterFunc(http3DrainTimeout, cancelExchanges)
			defer stop()
		} else {
			cancelExchanges()
		}
		exchanges.Wait()
		cancelExchanges()
		cancel()
		workers.Wait()
	}()
	heads := make(chan h3.Event)
	failures := make(chan error, 4)
	report := func(err error) {
		select {
		case failures <- err:
		case <-ctx.Done():
		}
	}
	workers.Go(func() { report(incoming.Run(ctx)) })
	workers.Go(func() { report(outgoing.Run(ctx)) })
	// Exactly one owner consumes each connection notification queue. Response
	// payloads stay in their per-stream queues and are read by exchange owners.
	workers.Go(func() {
		for {
			head, err := incoming.Receive(ctx)
			if err != nil {
				report(err)
				return
			}
			if head.Kind != h3.Headers {
				continue
			}
			select {
			case heads <- head:
			case <-ctx.Done():
				return
			}
		}
	})
	workers.Go(func() {
		for {
			if _, err := outgoing.Receive(ctx); err != nil {
				report(err)
				return
			}
		}
	})
	wire := newWireStore()
	for {
		select {
		case <-lifecycle.Done():
			return lifecycle.Err()
		case err := <-failures:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case head := <-heads:
			derived := *c
			var data hookdata.Context
			var route routeConfig
			if err := c.Do(ctx, func(context.Context) error {
				data = *c.Data
				route = l.exchangeRoute(c)
				return nil
			}); err != nil {
				return err
			}
			derived.Data = &data
			stream := &httpStream{c: &derived, id: StreamID(head.Identity.Stream), route: route, wire: wire}
			clientEndpoint := &http3Server{engine: incoming, identity: head.Identity, failureDone: incoming.StreamFailed(head.Identity), id: stream.id, normalize: normalize, logger: c.Logger, clock: c.Clock, head: &head}
			origin := &lazyServer{ready: make(chan struct{})}
			origin.acquire = func(ctx context.Context, request *httpmsg.Request) (ServerEndpoint, error) {
				return l.connect(ctx, &derived, stream, request, wire, endpoints, tlslayer.ServerSetup(&derived), origin)
			}
			exchanges.Go(func() {
				defer origin.release()
				defer func() {
					select {
					case <-incoming.StreamDone(head.Identity):
					default:
						_ = incoming.CancelStream(head.Identity, h3.ErrCodeRequestCancelled)
					}
				}()
				if err := (&streamDriver{stream: stream, client: clientEndpoint, server: origin}).run(exchangeCtx); err != nil {
					// External cancellation stops wire work immediately, but terminal
					// hook publication remains owned and joined by this exchange.
					if stream.flow != nil && !stream.done() {
						endCtx, stop := context.WithTimeout(context.WithoutCancel(lifecycle), layer.TerminalHookTimeout)
						_, endErr := stream.fail(endCtx, "peer closed connection", ClientDisconnected, err)
						stop()
						err = errors.Join(err, endErr)
					}
					if c.Logger != nil {
						c.Logger.DebugContext(exchangeCtx, "HTTP/3 exchange ended", "error", err)
					}
				}
			})
		}
	}
}

type http3OriginKey struct {
	address connection.Address
	sni     string
}

type http3Origin struct {
	ready     chan struct{}
	cancel    context.CancelFunc
	users     int
	borrowed  bool
	engine    *h3.Endpoint
	metadata  *connection.Server
	transport *quic.Transport
	conn      *quic.Conn
	err       error
}

// The packet pool remains handler-owned. This table owns only QUIC protocol
// sessions, and shares each establishment flight across concurrent exchanges.
type http3Origins struct {
	ctx     context.Context
	mu      sync.Mutex
	entries map[http3OriginKey]*http3Origin
	workers sync.WaitGroup
}

func newHTTP3Origins(ctx context.Context) *http3Origins {
	return &http3Origins{ctx: ctx, entries: make(map[http3OriginKey]*http3Origin)}
}

func http3Key(server *connection.Server) http3OriginKey {
	key := http3OriginKey{address: *server.Address}
	if server.SNI != nil {
		key.sni = *server.SNI
	}
	return key
}

func (o *http3Origins) borrow(server *connection.Server, conn *quic.Conn, engine *h3.Endpoint) {
	entry := &http3Origin{ready: make(chan struct{}), engine: engine, metadata: server, conn: conn, borrowed: true}
	close(entry.ready)
	o.entries[http3Key(server)] = entry
}

func (o *http3Origins) stop() {
	o.mu.Lock()
	entries := make([]*http3Origin, 0, len(o.entries))
	for _, entry := range o.entries {
		entries = append(entries, entry)
	}
	o.mu.Unlock()
	for _, entry := range entries {
		<-entry.ready
		if entry.transport != nil {
			if entry.conn != nil {
				_ = entry.conn.CloseWithError(quic.ApplicationErrorCode(h3.ErrCodeNoError), "")
			}
			_ = entry.transport.Close()
		}
	}
	o.workers.Wait()
}

func (o *http3Origins) acquire(ctx context.Context, c *layer.Context, server *connection.Server, stream *httpStream) (ServerEndpoint, func(), *connection.Server, error) {
	var key http3OriginKey
	if err := c.Do(ctx, func(context.Context) error {
		key = http3Key(server)
		return nil
	}); err != nil {
		return nil, nil, nil, err
	}
	for range 2 {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
		o.mu.Lock()
		entry := o.entries[key]
		if entry == nil {
			if len(o.entries) >= http3RetainedOrigins {
				for retainedKey, retained := range o.entries {
					if retained.borrowed || retained.users != 0 {
						continue
					}
					select {
					case <-retained.ready:
						delete(o.entries, retainedKey)
						if retained.cancel != nil {
							retained.cancel()
						}
					default:
						continue
					}
					break
				}
			}
			originCtx, cancelOrigin := context.WithCancel(o.ctx)
			entry = &http3Origin{ready: make(chan struct{}), metadata: server, cancel: cancelOrigin}
			// A full busy table must not refuse a valid destination. Such an
			// overflow session remains worker-owned but is not retained for reuse.
			if len(o.entries) < http3RetainedOrigins {
				o.entries[key] = entry
			}
			o.workers.Go(func() {
				defer cancelOrigin()
				entry.engine, entry.conn, entry.transport, entry.metadata, entry.err = dialHTTP3Origin(originCtx, c, server)
				close(entry.ready)
				if entry.err != nil {
					return
				}
				o.workers.Go(func() {
					for {
						if _, err := entry.engine.Receive(originCtx); err != nil {
							return
						}
					}
				})
				_ = entry.engine.Run(originCtx)
				_ = entry.conn.CloseWithError(quic.ApplicationErrorCode(h3.ErrCodeNoError), "")
				_ = entry.transport.Close()
				o.mu.Lock()
				if o.entries[key] == entry {
					delete(o.entries, key)
				}
				o.mu.Unlock()
			})
		}
		entry.users++
		o.mu.Unlock()
		releaseLease := sync.OnceFunc(func() {
			o.mu.Lock()
			entry.users--
			if entry.users == 0 && !entry.borrowed && o.entries[key] != entry {
				entry.cancel()
			}
			o.mu.Unlock()
		})
		select {
		case <-entry.ready:
		case <-ctx.Done():
			releaseLease()
			return nil, nil, nil, ctx.Err()
		}
		if entry.err != nil {
			releaseLease()
			return nil, nil, nil, entry.err
		}
		identity, err := entry.engine.OpenStream(ctx)
		if err != nil {
			if errors.Is(err, h3.ErrDraining) || entry.conn.Context().Err() != nil {
				o.mu.Lock()
				if o.entries[key] == entry {
					delete(o.entries, key)
				}
				o.mu.Unlock()
				releaseLease()
				continue
			}
			releaseLease()
			return nil, nil, nil, err
		}
		settings, err := protocolSettings(ctx, c, entry.metadata)
		if err != nil {
			_ = entry.engine.CancelStream(identity, h3.ErrCodeRequestCancelled)
			releaseLease()
			return nil, nil, nil, err
		}
		endpoint := &http3Client{engine: entry.engine, identity: identity, failureDone: entry.engine.StreamFailed(identity), id: stream.id, normalize: settings.normalize, logger: c.Logger, clock: c.Clock}
		release := sync.OnceFunc(func() {
			select {
			case <-entry.engine.StreamDone(identity):
			default:
				_ = entry.engine.CancelStream(identity, h3.ErrCodeRequestCancelled)
			}
			releaseLease()
		})
		return endpoint, release, entry.metadata, nil
	}
	return nil, nil, nil, errors.New("httplayer: HTTP/3 origin is unavailable")
}

func dialHTTP3Origin(ctx context.Context, c *layer.Context, server *connection.Server) (*h3.Endpoint, *quic.Conn, *quic.Transport, *connection.Server, error) {
	if c.OpenPackets == nil || c.RecordPackets == nil {
		return nil, nil, nil, nil, errors.New("httplayer: HTTP/3 origin requires packet acquisition")
	}
	packets, actual, err := c.OpenPackets(ctx, server)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	derived := *c
	var data hookdata.Context
	derived.Data = &data
	if err := c.Do(ctx, func(context.Context) error {
		data = *c.Data
		data.Server, actual.TLS = actual, true
		return nil
	}); err != nil {
		return nil, nil, nil, nil, err
	}
	conf, err := http3OriginTLS(ctx, &derived)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	recorded := c.RecordPackets(packets)
	recorded.StopRecording()
	transport := &quic.Transport{Conn: recorded}
	conn, err := transport.Dial(ctx, packets.RemoteAddr(), conf, &quic.Config{MaxIncomingStreams: h3.MaxConcurrentStreams, MaxIncomingUniStreams: 100})
	if err != nil {
		_ = transport.Close()
		return nil, nil, nil, nil, err
	}
	settings, err := protocolSettings(ctx, &derived, actual)
	if err == nil {
		state := conn.ConnectionState().TLS
		_, err = c.Hooks.FireFunc(ctx, func(context.Context) error {
			actual.TLSVersion, actual.ALPN = connection.QUICv1, []byte(state.NegotiatedProtocol)
			actual.Cipher = new(strings.TrimPrefix(tls.CipherSuiteName(state.CipherSuite), "TLS_"))
			actual.CertificateList = nil
			for _, certificate := range state.PeerCertificates {
				actual.CertificateList = append(actual.CertificateList, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
			}
			return nil
		}, addon.TLSEstablishedServerHook{Data: &hookdata.TLS{Context: &data, Conn: &actual.Connection}})
	}
	var engine *h3.Endpoint
	if err == nil {
		settings.descriptor.Protocol = "h3"
		engine, err = h3.New(conn, h3.Config{Descriptor: settings.descriptor, Client: true, ValidateInboundHeaders: settings.validate, Logger: c.Logger})
	}
	if err != nil {
		_ = conn.CloseWithError(quic.ApplicationErrorCode(h3.ErrCodeNoError), "")
		_ = transport.Close()
		return nil, nil, nil, nil, err
	}
	return engine, conn, transport, actual, nil
}

// Hook-owned settings are copied under dispatch; opaque signing keys remain
// shared immutable values, exactly as crypto/tls.Config.Clone treats them.
func http3OriginTLS(ctx context.Context, c *layer.Context) (*tls.Config, error) {
	data := &hookdata.QUICTLS{}
	if _, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
		data.Context, data.Conn = c.Data, &c.Data.Server.Connection
		return nil
	}, addon.QUICStartServerHook{Data: data}); err != nil {
		return nil, err
	}
	conf := &tls.Config{MinVersion: tls.VersionTLS13}
	var paths []string
	var directory, requiredPath string
	if err := c.Do(ctx, func(context.Context) error {
		settings := data.Settings
		if settings == nil {
			return errors.New("httplayer: no QUIC TLS settings for origin")
		}
		conf.NextProtos = slices.Clone(settings.ALPNProtocols)
		if data.Conn.SNI != nil {
			conf.ServerName = *data.Conn.SNI
		} else {
			conf.ServerName = c.Data.Server.Address.Host
		}
		conf.InsecureSkipVerify = settings.VerifyMode != nil && *settings.VerifyMode == hookdata.VerifyNone
		if settings.Certificate != nil {
			certificate := tls.Certificate{Certificate: [][]byte{bytes.Clone(settings.Certificate.Raw)}, PrivateKey: settings.CertificatePrivateKey}
			for _, cert := range settings.CertificateChain {
				if cert == nil {
					return errors.New("httplayer: nil certificate in QUIC chain")
				}
				certificate.Certificate = append(certificate.Certificate, bytes.Clone(cert.Raw))
			}
			conf.Certificates = []tls.Certificate{certificate}
		}
		if settings.CAFile != nil {
			requiredPath = *settings.CAFile
			paths = append(paths, requiredPath)
		}
		if settings.CAPath != nil {
			directory = *settings.CAPath
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if directory != "" {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, fmt.Errorf("httplayer: QUIC trusted CA directory: %w", err)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				paths = append(paths, filepath.Join(directory, entry.Name()))
			}
		}
	}
	if len(paths) != 0 {
		conf.RootCAs = x509.NewCertPool()
		for _, path := range paths {
			required := path == requiredPath
			pem, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				if required {
					return nil, fmt.Errorf("httplayer: QUIC trusted CA: %w", err)
				}
				if c.Logger != nil {
					c.Logger.WarnContext(ctx, "Reading QUIC trusted CA directory entry", "error", err)
				}
				continue
			}
			if !conf.RootCAs.AppendCertsFromPEM(pem) && required {
				return nil, errors.New("httplayer: QUIC trusted CA contains no certificates")
			}
		}
	}
	return conf, nil
}
