// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build proxybench

// Package bench exercises proxy throughput with owned client and origin endpoints.
package bench

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/addons/proxyserver"
	"github.com/zchee/mitmproxy-go/addons/tlsconfig"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
	"github.com/zchee/mitmproxy-go/internal/telemetry"
	"github.com/zchee/mitmproxy-go/internal/version"
	"github.com/zchee/mitmproxy-go/master"

	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/httplayer"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/modes"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/tlslayer"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/websocket"
)

const (
	bodyChunk                 = 32 << 10
	retainedWebSocketMessages = 1
	quicKeepAlivePeriod       = 10 * time.Second
)

type boundedHistory struct{}

func (*boundedHistory) WebSocketMessage(_ context.Context, f *flow.HTTPFlow) error {
	messages := f.WebSocket.Messages
	if len(messages) > retainedWebSocketMessages {
		last := messages[len(messages)-retainedWebSocketMessages:]
		copy(messages, last)
		clear(messages[retainedWebSocketMessages:])
		f.WebSocket.Messages = messages[:retainedWebSocketMessages]
	}
	return nil
}

// patternReader produces binary bodies without retaining a body-sized allocation.
type patternReader struct{ remaining, position int }

func (r *patternReader) Read(p []byte) (int, error) {
	n := min(len(p), r.remaining)
	if n == 0 {
		return 0, io.EOF
	}
	for i := range n {
		p[i] = byte((r.position + i) % 251)
	}
	r.remaining -= n
	r.position += n
	return n, nil
}

type bodyCheck struct {
	size int
	want [sha256.Size]byte
	hash hash.Hash
	buf  []byte
	sum  []byte
}

func newBodyCheck(size int) *bodyCheck {
	digest := sha256.New()
	buf := make([]byte, bodyChunk)
	_, _ = io.CopyBuffer(digest, &patternReader{remaining: size}, buf)
	check := &bodyCheck{size: size, hash: digest, buf: buf, sum: make([]byte, 0, sha256.Size)}
	copy(check.want[:], digest.Sum(check.sum))
	return check
}

func (c *bodyCheck) read(r io.Reader) error {
	c.hash.Reset()
	n, err := io.CopyBuffer(c.hash, io.LimitReader(r, int64(c.size)+1), c.buf)
	if err != nil {
		return err
	}
	if n != int64(c.size) || !bytes.Equal(c.hash.Sum(c.sum[:0]), c.want[:]) {
		return fmt.Errorf("body mismatch: received %d bytes, want %d with checksum %x", n, c.size, c.want)
	}
	return nil
}

func writeBody(w io.Writer, size int, buf []byte) error {
	_, err := io.CopyBuffer(w, &patternReader{remaining: size}, buf)
	return err
}

type benchPeer struct {
	jobs  chan (<-chan struct{})
	done  chan error
	close func() error
}

type harness struct {
	ctx         context.Context
	cancel      context.CancelFunc
	master      *master.Master
	telemetry   *telemetry.Controller
	collector   *ownedCollector
	listeners   []netip.AddrPort
	connections *proxy.Connections
	accepted    atomic.Int64
	origins     atomic.Int64
	completed   atomic.Int64
	blocking    atomic.Bool
	started     chan struct{}
	workers     sync.WaitGroup
	proxyWork   sync.WaitGroup
	originWork  sync.WaitGroup
	peers       []*benchPeer
	closeProxy  func() error
	closeOrigin func() error
	errors      chan error
	closed      bool
}

func newHarness(tb testing.TB, parent context.Context, protocol string, count, size int, enabled bool) *harness {
	tb.Helper()
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	h := &harness{ctx: ctx, cancel: cancel, connections: new(proxy.Connections), errors: make(chan error, 2*count+8), started: make(chan struct{}, count)}
	tb.Cleanup(func() {
		if err := h.close(); err != nil {
			tb.Error(err)
		}
	})
	origin := h.startOrigin(tb, protocol, size)
	logger := slog.New(slog.DiscardHandler)
	masterConfig := master.Config{Logger: logger}
	var fidelity *http1.FidelityCounter
	if enabled {
		h.collector = newOwnedCollector()
		fidelity = new(http1.FidelityCounter)
		h.telemetry = telemetry.New(telemetry.Config{
			Fidelity: fidelity, Connections: h.connections.Len,
			Listeners: func() []netip.AddrPort { return h.listeners },
			Version:   version.Version, Logger: logger,
		})
		masterConfig.OnHookComplete = h.telemetry.OnHookComplete
		masterConfig.OnDispatchStart = h.telemetry.OnDispatchStart
		masterConfig.OnDispatchEnd = h.telemetry.OnDispatchEnd
	}
	m := master.New(masterConfig)
	h.master = m
	if h.telemetry != nil {
		h.telemetry.Bind(m)
	}
	cfg := proxy.Config{Manager: m.Addons, Options: m.Options, Connections: h.connections, HTTPFidelity: fidelity, Logger: logger}
	defaults, err := proxyserver.New(cfg)
	if err != nil {
		tb.Fatal(err)
	}
	security := tlsconfig.New(m.Options)
	confdir := tb.TempDir()
	if err := m.Do(ctx, func(ctx context.Context) error {
		if err := m.Options.Update(ctx, map[string]any{"confdir": confdir}); err != nil {
			return err
		}
		if err := m.Addons.Add(ctx, defaults, nextlayer.New(m.Options), security); err != nil {
			return err
		}
		if h.telemetry != nil {
			if err := m.Addons.Add(ctx, h.telemetry); err != nil {
				return err
			}
		}
		if protocol == "ws" {
			if err := m.Addons.Add(ctx, &boundedHistory{}); err != nil {
				return err
			}
		}
		return m.Options.Update(ctx, map[string]any{
			"confdir": confdir, "server": false, "ssl_insecure": true,
			"connection_strategy": "lazy", "stream_large_bodies": "32k",
		})
	}); err != nil {
		tb.Fatal(err)
	}
	pem, err := os.ReadFile(filepath.Join(confdir, "mitmproxy-ca-cert.pem")) //nolint:gosec // The harness owns the temporary directory holding its generated public CA.
	if err != nil {
		tb.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		tb.Fatal("proxy CA is not a certificate")
	}
	handler, err := proxy.NewHandler(cfg)
	if err != nil {
		tb.Fatal(err)
	}
	scheme := "http"
	switch protocol {
	case "h2":
		scheme = "https"
	case "h3":
		scheme = "http3"
	}
	mode := "reverse:" + scheme + "://" + origin
	address := h.startProxy(tb, handler, mode, protocol)
	if h.telemetry != nil {
		listener, err := netip.ParseAddrPort(address)
		if err != nil {
			tb.Fatal(err)
		}
		h.listeners = []netip.AddrPort{listener}
		if err := m.Do(ctx, func(ctx context.Context) error {
			if err := m.Options.Update(ctx, map[string]any{"otel_exporter_endpoint": h.collector.server.URL}); err != nil {
				return err
			}
			return m.Addons.Hook(ctx, addon.RunningHook{})
		}); err != nil {
			tb.Fatal(err)
		}
		if err := h.telemetry.Sync(ctx); err != nil {
			tb.Fatal(err)
		}
		if status := h.telemetry.Status(); !status.Enabled || status.ExportFailures != 0 {
			tb.Fatalf("telemetry startup: %+v", status)
		}
	}
	for range count {
		var exchange func() error
		var closePeer func() error
		if protocol == "ws" {
			exchange, closePeer = h.webSocketPeer(tb, address, size)
		} else {
			exchange, closePeer = h.httpPeer(tb, protocol, address, roots, size)
		}
		peer := &benchPeer{jobs: make(chan (<-chan struct{})), done: make(chan error, 1), close: closePeer}
		h.peers = append(h.peers, peer)
		// Establish transport and validate the complete useful body before timing.
		if err := exchange(); err != nil {
			tb.Fatalf("%s warmup: %v", protocol, err)
		}
		h.workers.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case barrier := <-peer.jobs:
					select {
					case <-ctx.Done():
						peer.done <- ctx.Err()
					case <-barrier:
						peer.done <- exchange()
					}
				}
			}
		})
	}
	h.checkCounts(tb)
	return h
}

func (h *harness) report(err error) {
	if err != nil && h.ctx.Err() == nil {
		select {
		case h.errors <- err:
		default:
			h.cancel()
		}
	}
}

func (h *harness) startProxy(tb testing.TB, handler *proxy.Handler, mode, protocol string) string {
	tb.Helper()
	top := hookdata.LayerSpec{Kind: hookdata.LayerReverse}
	if protocol == "h3" {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			tb.Fatal(err)
		}
		listener := packettransport.NewListener(h.ctx, socket)
		h.closeProxy = listener.Close
		h.proxyWork.Go(func() {
			for {
				conn, err := listener.Accept(h.ctx)
				if err != nil {
					h.report(err)
					return
				}
				h.accepted.Add(1)
				h.proxyWork.Go(func() {
					if err := handler.HandlePackets(h.ctx, conn, mode, top); err != nil {
						h.report(fmt.Errorf("proxy tuple %s: %w (transport cause: %v)", conn.RemoteAddr(), err, context.Cause(conn.Context())))
					}
				})
			}
		})
		return socket.LocalAddr().String()
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	h.closeProxy = listener.Close
	h.proxyWork.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				h.report(err)
				return
			}
			h.accepted.Add(1)
			h.proxyWork.Go(func() { h.report(handler.Handle(h.ctx, conn, mode, top)) })
		}
	})
	return listener.Addr().String()
}

func (h *harness) startOrigin(tb testing.TB, protocol string, size int) string {
	tb.Helper()
	if protocol == "ws" {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			tb.Fatal(err)
		}
		var mu sync.Mutex
		conns := make(map[net.Conn]struct{})
		h.closeOrigin = func() error {
			err := listener.Close()
			mu.Lock()
			for conn := range conns {
				_ = conn.Close()
			}
			mu.Unlock()
			return err
		}
		h.originWork.Go(func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					h.report(err)
					return
				}
				h.origins.Add(1)
				mu.Lock()
				conns[conn] = struct{}{}
				mu.Unlock()
				h.originWork.Go(func() {
					defer func() { _ = conn.Close(); mu.Lock(); delete(conns, conn); mu.Unlock() }()
					if _, err := gows.Upgrade(conn); err != nil {
						h.report(err)
						return
					}
					ws := gows.NewServerConn(conn)
					check := newBodyCheck(size)
					for {
						op, reader, err := ws.NextReader()
						if err != nil {
							if !errors.Is(err, io.EOF) {
								h.report(err)
							}
							return
						}
						if op != gows.OpcodeBinary {
							h.report(fmt.Errorf("origin WebSocket opcode %v is not binary", op))
							return
						}
						if err := check.read(reader); err != nil {
							h.report(err)
							return
						}
						writer, err := ws.NextWriter(gows.OpcodeBinary)
						if err != nil {
							h.report(err)
							return
						}
						err = errors.Join(writeBody(writer, size, check.buf), writer.Close())
						if err != nil {
							h.report(err)
							return
						}
						h.completed.Add(1)
					}
				})
			}
		})
		return listener.Addr().String()
	}
	serve := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.blocking.Load() {
			h.started <- struct{}{}
			<-h.ctx.Done()
			return
		}
		check := newBodyCheck(size)
		if r.Method != http.MethodPost || r.ContentLength != int64(size) {
			h.report(fmt.Errorf("origin request: method=%s bytes=%d", r.Method, r.ContentLength))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := check.read(r.Body); err != nil {
			h.report(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		if err := writeBody(w, size, check.buf); err != nil {
			h.report(err)
			return
		}
		h.completed.Add(1)
	})
	origin := httptest.NewUnstartedServer(serve)
	origin.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			h.origins.Add(1)
		}
	}
	origin.EnableHTTP2 = protocol == "h2"
	if protocol == "h1" {
		origin.Start()
		h.closeOrigin = func() error { origin.Close(); return nil }
		return origin.Listener.Addr().String()
	}
	origin.StartTLS()
	if protocol == "h2" {
		h.closeOrigin = func() error { origin.Close(); return nil }
		return origin.Listener.Addr().String()
	}
	config := origin.TLS.Clone()
	origin.Close()
	listener, err := quic.ListenAddr("127.0.0.1:0", http3.ConfigureTLSConfig(config), &quic.Config{KeepAlivePeriod: quicKeepAlivePeriod})
	if err != nil {
		tb.Fatal(err)
	}
	server := &http3.Server{Handler: serve}
	h.closeOrigin = func() error { return errors.Join(server.Close(), listener.Close()) }
	h.originWork.Go(func() {
		for {
			conn, err := listener.Accept(h.ctx)
			if err != nil {
				h.report(err)
				return
			}
			h.origins.Add(1)
			h.originWork.Go(func() { h.report(server.ServeQUICConn(conn)) })
		}
	})
	return listener.Addr().String()
}

func (h *harness) httpPeer(tb testing.TB, protocol, address string, roots *x509.CertPool, size int) (func() error, func() error) {
	tb.Helper()
	var roundTrip func(*http.Request) (*http.Response, error)
	var closePeer func() error
	scheme := "http"
	if protocol == "h3" {
		scheme = "https"
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			tb.Fatal(err)
		}
		transport := &quic.Transport{Conn: socket}
		addr, err := net.ResolveUDPAddr("udp4", address)
		if err != nil {
			tb.Fatal(err)
		}
		conn, err := transport.Dial(h.ctx, addr, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{http3.NextProtoH3}, MinVersion: tls.VersionTLS13}, &quic.Config{KeepAlivePeriod: quicKeepAlivePeriod})
		if err != nil {
			_ = transport.Close()
			_ = socket.Close()
			tb.Fatal(err)
		}
		if got := conn.ConnectionState().TLS.NegotiatedProtocol; got != http3.NextProtoH3 {
			tb.Fatalf("ALPN=%q, want h3", got)
		}
		httpTransport := &http3.Transport{}
		client := httpTransport.NewClientConn(conn)
		roundTrip = client.RoundTrip
		closePeer = func() error {
			_ = conn.CloseWithError(0, "")
			return errors.Join(httpTransport.Close(), transport.Close(), socket.Close())
		}
	} else {
		protocols := new(http.Protocols)
		protocols.SetHTTP1(protocol == "h1")
		protocols.SetHTTP2(protocol == "h2")
		var dials atomic.Int64
		transport := &http.Transport{
			Protocols: protocols, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1,
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
				if target != address {
					return nil, fmt.Errorf("refusing unexpected client target %q", target)
				}
				if dials.Add(1) != 1 {
					return nil, errors.New("client tried to open a second transport connection")
				}
				return new(net.Dialer).DialContext(ctx, "tcp4", address)
			},
		}
		if protocol == "h2" {
			scheme = "https"
		}
		roundTrip = transport.RoundTrip
		closePeer = func() error { transport.CloseIdleConnections(); return nil }
	}
	check := newBodyCheck(size)
	return func() error {
		request, err := http.NewRequestWithContext(h.ctx, http.MethodPost, scheme+"://"+address+"/body", &patternReader{remaining: size})
		if err != nil {
			return err
		}
		request.ContentLength = int64(size)
		response, err := roundTrip(request)
		if err != nil {
			return err
		}
		defer func() { _ = response.Body.Close() }()
		wantProto := map[string]int{"h1": 1, "h2": 2, "h3": 3}[protocol]
		if response.StatusCode != http.StatusOK || response.ProtoMajor != wantProto || response.ContentLength != int64(size) {
			return fmt.Errorf("response: status=%d protocol=%s bytes=%d", response.StatusCode, response.Proto, response.ContentLength)
		}
		if protocol == "h2" && (response.TLS == nil || response.TLS.NegotiatedProtocol != "h2") {
			return errors.New("HTTP/2 was not negotiated over TLS")
		}
		return check.read(response.Body)
	}, closePeer
}

func (h *harness) webSocketPeer(tb testing.TB, address string, size int) (func() error, func() error) {
	tb.Helper()
	conn, handshake, err := gows.Dial(h.ctx, "ws://"+address+"/body")
	if err != nil {
		tb.Fatal(err)
	}
	ws := gows.NewClientConn(conn, gows.WithBuffered(handshake.Buffered))
	check := newBodyCheck(size)
	return func() error {
		writer, err := ws.NextWriter(gows.OpcodeBinary)
		if err != nil {
			return err
		}
		if err := errors.Join(writeBody(writer, size, check.buf), writer.Close()); err != nil {
			return err
		}
		op, reader, err := ws.NextReader()
		if err != nil {
			return err
		}
		if op != gows.OpcodeBinary {
			return fmt.Errorf("echo opcode=%v, want binary", op)
		}
		return check.read(reader)
	}, conn.Close
}

func (h *harness) batch() error {
	barrier := make(chan struct{})
	admitted := 0
	for _, peer := range h.peers {
		select {
		case <-h.ctx.Done():
			close(barrier)
			return h.ctx.Err()
		case peer.jobs <- barrier:
			admitted++
		}
	}
	close(barrier)
	var result error
	for _, peer := range h.peers[:admitted] {
		select {
		case <-h.ctx.Done():
			return errors.Join(result, h.ctx.Err())
		case err := <-peer.done:
			result = errors.Join(result, err)
		}
	}
	return result
}

func (h *harness) checkCounts(tb testing.TB) {
	tb.Helper()
	want := int64(len(h.peers))
	if h.accepted.Load() != want || h.origins.Load() != want {
		tb.Fatalf("accepted proxy=%d origin=%d, want %d actual connections each", h.accepted.Load(), h.origins.Load(), want)
	}
}

func (h *harness) close() error {
	if h.closed {
		return nil
	}
	h.closed = true
	h.cancel()
	var result error
	for _, peer := range h.peers {
		result = errors.Join(result, peer.close())
	}
	if h.closeProxy != nil {
		_ = h.closeProxy()
	}
	h.connections.Close()
	h.workers.Wait()
	h.proxyWork.Wait()
	if h.closeOrigin != nil {
		_ = h.closeOrigin()
	}
	h.originWork.Wait()
	if h.connections.Len() != 0 {
		result = errors.Join(result, errors.New("proxy retained a joined client connection"))
	}
	if h.telemetry != nil {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(h.ctx), 10*time.Second)
		result = errors.Join(result, h.telemetry.Close(ctx))
		cancel()
		if status := h.telemetry.Status(); status.Enabled || !status.Stopped || status.ActiveFlows != 0 || status.ActiveConnections != 0 || status.ExportFailures != 0 {
			result = errors.Join(result, fmt.Errorf("telemetry shutdown: %+v", status))
		}
	}
	if h.master != nil {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(h.ctx), 10*time.Second)
		result = errors.Join(result, h.master.Close(ctx))
		cancel()
	}
	if h.collector != nil {
		h.collector.server.Close()
		if spans, metrics, failures := h.collector.spans.Load(), h.collector.metrics.Load(), h.collector.failures.Load(); spans == 0 || metrics == 0 || failures != 0 {
			result = errors.Join(result, fmt.Errorf("owned collector: spans=%d metrics=%d failures=%d", spans, metrics, failures))
		}
	}
	for {
		select {
		case err := <-h.errors:
			result = errors.Join(result, err)
		default:
			return result
		}
	}
}
