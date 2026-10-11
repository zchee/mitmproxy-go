// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build h2load

package httplayer

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/quic-go/qpack"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/addons/proxyserver"
	"github.com/zchee/mitmproxy-go/addons/tlsconfig"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/internal/proxy/modeserver"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/master"
)

const (
	http3LoadTransferLimit = 30 * time.Second
	http3LoadSiblingLimit  = 2 * time.Second
	http3LoadChunkSize     = 64 << 10
	http3LoadSiblingSize   = 4 << 20
)

type loadHTTP3Session struct {
	ctx       context.Context
	client    *quic.Conn
	master    *master.Master
	authority string
	receipt   *loadHTTP3Receipt
}

func newLoadHTTP3Session(t *testing.T, observer *streamAddon, receipt *loadHTTP3Receipt) *loadHTTP3Session {
	t.Helper()
	if os.Getenv("MITMPROXY_GO_HTTP2_LOAD") != "1" {
		receipt.fail("setup-opt-in", errors.New("h2load requires MITMPROXY_GO_HTTP2_LOAD=1 and an isolated runner"))
		t.Fatal("h2load requires MITMPROXY_GO_HTTP2_LOAD=1 and an isolated runner")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	logger := slog.New(slog.DiscardHandler)
	m := master.New(master.Config{Logger: logger})
	t.Cleanup(func() {
		if err := m.Close(context.WithoutCancel(ctx)); err != nil {
			t.Error(err)
		}
	})
	connections := new(proxy.Connections)
	cfg := proxy.Config{Manager: m.Addons, Options: m.Options, Connections: connections, Logger: logger}
	defaults, err := proxyserver.New(cfg)
	if err != nil {
		receipt.fail("", err)
		t.Fatal(err)
	}
	security := tlsconfig.New(m.Options)
	confdir := t.TempDir()
	if err := m.Do(ctx, func(ctx context.Context) error {
		if err := m.Addons.Add(ctx, defaults, nextlayer.New(m.Options)); err != nil {
			return err
		}
		if err := m.Options.Set(ctx, "confdir="+confdir, "ssl_insecure=true", "connection_strategy=lazy", "stream_large_bodies=1m"); err != nil {
			return err
		}
		if err := m.Addons.Add(ctx, security, observer); err != nil {
			return err
		}
		return security.Configure(ctx, map[string]struct{}{"confdir": {}})
	}); err != nil {
		receipt.fail("setup-configure", err)
		t.Fatal(err)
	}
	receipt.phaseStream("setup-origin-listener", nil)
	originListener, target := newHTTP3RoutingListener(t, func(err error) { receipt.fail("setup-origin-listener", err) })
	handler, err := proxy.NewHandler(cfg)
	if err != nil {
		receipt.fail("", err)
		t.Fatal(err)
	}
	mode, err := modespec.Parse("reverse:http3://" + target.String())
	if err != nil {
		receipt.fail("", err)
		t.Fatal(err)
	}
	instance, err := modeserver.New(mode, modeserver.Config{Handler: handler, ListenHost: "127.0.0.1", ListenPort: new(0), Logger: logger})
	if err != nil {
		receipt.fail("", err)
		t.Fatal(err)
	}
	receipt.phaseStream("setup-proxy-start", nil)
	if err := instance.Start(ctx); err != nil {
		receipt.fail("setup-proxy-start", err)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		connections.Close()
		if err := instance.Stop(); err != nil {
			t.Error(err)
		}
	})
	addresses := instance.ListenAddrs()
	if len(addresses) != 1 {
		receipt.fail("setup-proxy-address", fmt.Errorf("reverse HTTP3 listener addresses = %v, want one UDP listener", addresses))
		t.Fatalf("reverse HTTP3 listener addresses = %v, want one UDP listener", addresses)
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		origin, err := originListener.Accept(ctx)
		if err != nil {
			if ctx.Err() == nil {
				receipt.fail("origin-handshake", err)
				receipt.publish()
				t.Errorf("accept HTTP3 origin: %v", err)
			}
			return
		}
		receipt.mu.Lock()
		receipt.origin = origin
		receipt.mu.Unlock()
		defer func() { _ = origin.CloseWithError(0x100, "") }()
		defer func() {
			if t.Failed() {
				receipt.publish()
			}
		}()
		stop := context.AfterFunc(ctx, func() {
			receipt.fail("owner-context", context.Cause(ctx))
			receipt.publish()
			_ = origin.CloseWithError(0x100, "")
		})
		defer stop()
		startHTTP3RoutingPeer(t, ctx, origin, func(err error) {
			if receipt.fail("origin-control", err) {
				receipt.publish()
				t.Errorf("HTTP3 origin control stream: %v", err)
			}
		})
		chunk := make([]byte, http3LoadChunkSize)
		for {
			request, err := origin.AcceptStream(ctx)
			if err != nil {
				if ctx.Err() == nil {
					receipt.fail("origin-request-accept", err)
					receipt.publish()
					t.Errorf("accept HTTP3 request: %v", err)
				}
				return
			}
			workers.Go(func() {
				defer func() {
					if t.Failed() {
						receipt.publish()
					}
				}()
				fields, body, trailers := readLoadHTTP3Message(t, request, receipt)
				if len(body) != 0 || len(trailers) != 0 {
					receipt.fail("origin-request-validation", errors.New("download request unexpectedly contains a body or trailers"))
					t.Error("download request unexpectedly contains a body or trailers")
					return
				}
				var path string
				for _, field := range fields {
					if field.Name == ":path" {
						path = field.Value
					}
				}
				var size int64
				switch path {
				case "/warm":
					size = http3LoadChunkSize
				case "/download":
					size = loadBodySize
				case "/small":
					size = http3LoadSiblingSize
				default:
					receipt.fail("origin-request-path", fmt.Errorf("unexpected HTTP3 origin request path %q", path))
					t.Errorf("unexpected HTTP3 origin request path %q", path)
					return
				}
				writer := loadHTTP3Writer{request, receipt, "origin-response-write"}
				writeHTTP3TestHeaders(t, writer, []qpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-length", Value: strconv.FormatInt(size, 10)}})
				for remaining := size; remaining > 0; {
					n := min(remaining, int64(len(chunk)))
					writeHTTP3TestFrame(t, writer, 0, chunk[:n])
					remaining -= n
				}
				if err := request.Close(); err != nil && ctx.Err() == nil {
					receipt.fail("origin-response-close", err)
					t.Errorf("close HTTP3 response: %v", err)
				}
			})
		}
	})
	t.Cleanup(func() { cancel(); workers.Wait() })
	receipt.phaseStream("setup-client-socket", nil)
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		receipt.fail("", err)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	transport := &quic.Transport{Conn: socket}
	t.Cleanup(func() { _ = transport.Close() })
	address, err := net.ResolveUDPAddr("udp4", addresses[0].String())
	if err != nil {
		receipt.fail("", err)
		t.Fatal(err)
	}
	receipt.phaseStream("client-handshake", nil)
	client, err := transport.Dial(ctx, address, &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, ServerName: "localhost", InsecureSkipVerify: true}, nil)
	if err != nil {
		receipt.fail("", err)
		t.Fatal(err)
	}
	receipt.mu.Lock()
	receipt.client = client
	receipt.mu.Unlock()
	startHTTP3RoutingPeer(t, ctx, client, func(err error) {
		if receipt.fail("client-control", err) {
			receipt.publish()
			t.Errorf("HTTP3 client control stream: %v", err)
		}
	})
	s := &loadHTTP3Session{ctx: ctx, client: client, master: m, authority: target.String(), receipt: receipt}
	receipt.mu.Lock()
	expected := receipt.expected
	receipt.stage, receipt.expected = "warmup-", http3LoadChunkSize
	receipt.mu.Unlock()
	readLoadHTTP3Body(t, s.request(t, "/warm", true), http3LoadChunkSize, receipt)
	receipt.mu.Lock()
	receipt.stage, receipt.expected = "", expected
	receipt.mu.Unlock()
	receipt.actual.Store(0)
	receipt.validated.Store(0)
	return s
}

func (s *loadHTTP3Session) request(t *testing.T, path string, end bool) *quic.Stream {
	t.Helper()
	receipt := s.receipt
	receipt.phaseStream("request-open:"+path, nil)
	stream, err := s.client.OpenStreamSync(s.ctx)
	if err != nil {
		receipt.fail("", err)
		t.Fatal(err)
	}
	s.receipt.phaseStream("request", stream)
	writeHTTP3TestHeaders(t, loadHTTP3Writer{stream, s.receipt, "request-write"}, []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: s.authority}, {Name: ":path", Value: path}})
	if end {
		if err := stream.Close(); err != nil {
			receipt.fail("request-close", err)
			t.Fatal(err)
		}
	}
	return stream
}

// Retain only a framing buffer, so the client does not accumulate the download.
func readLoadHTTP3Body(t *testing.T, stream *quic.Stream, size int64, receipt *loadHTTP3Receipt) {
	t.Helper()
	receipt.phaseStream("headers", stream)
	want := []qpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-length", Value: strconv.FormatInt(size, 10)}}
	if diff := gocmp.Diff(want, readHTTP3TestHeaders(t, loadHTTP3Reader{stream, receipt, "headers"})); diff != "" {
		receipt.fail("headers", fmt.Errorf("HTTP3 response headers (-want +got):\n%s", diff))
		t.Fatalf("HTTP3 response headers (-want +got):\n%s", diff)
	}
	receipt.phaseStream("body", stream)
	reader := quicvarint.NewReader(stream)
	buffer := make([]byte, http3LoadChunkSize)
	var received int64
	for {
		kind, err := quicvarint.Read(reader)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			receipt.fail("frame-read", err)
			t.Fatal(err)
		}
		length, err := quicvarint.Read(reader)
		if err != nil || kind != 0 || length > uint64(size-received) {
			cause := err
			if cause == nil {
				cause = fmt.Errorf("HTTP3 response frame kind=%d length=%d received=%d", kind, length, received)
			}
			receipt.fail("frame", cause)
			t.Fatalf("HTTP3 response frame kind=%d length=%d received=%d error=%v", kind, length, received, err)
		}
		for remaining := int64(length); remaining > 0; {
			n := min(remaining, int64(len(buffer)))
			actual, err := io.ReadFull(reader, buffer[:n])
			// Account delivered payload even when the same read reports a terminal error.
			receipt.actual.Add(int64(actual))
			if err != nil {
				receipt.fail("body-read", err)
				t.Fatal(err)
			}
			if bytes.Count(buffer[:n], []byte{0}) != int(n) {
				receipt.fail("body-validation", errors.New("HTTP3 response body differs from origin payload"))
				t.Fatal("HTTP3 response body differs from origin payload")
			}
			received += n
			receipt.validated.Add(n)
			remaining -= n
		}
	}
	if received != size {
		receipt.fail("body-length", fmt.Errorf("HTTP3 response bytes = %d, want %d", received, size))
		t.Fatalf("HTTP3 response bytes = %d, want %d", received, size)
	}
	receipt.phaseStream("transfer-eof", stream)
}

func TestHTTP3LoadLargeTransfer(t *testing.T) {
	tests := map[string]struct{ size int64 }{"success: 64 MiB download through reverse HTTP3": {size: loadBodySize}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			receipt := newLoadHTTP3Receipt(t, test.size)
			defer receipt.publish()
			s := newLoadHTTP3Session(t, new(streamAddon), receipt)
			started := time.Now()
			receipt.started.Store(&started)
			request := s.request(t, "/download", true)
			if err := request.SetReadDeadline(started.Add(http3LoadTransferLimit)); err != nil {
				receipt.fail("read-deadline", err)
				t.Fatal(err)
			}
			readLoadHTTP3Body(t, request, test.size, receipt)
			elapsed := receipt.freezeElapsed()
			t.Logf("HTTP3 reverse download: bytes=%d duration=%s duration_ns=%d limit=%s", test.size, elapsed, elapsed.Nanoseconds(), http3LoadTransferLimit)
			if elapsed > http3LoadTransferLimit {
				receipt.fail("elapsed-limit", fmt.Errorf("HTTP3 download duration = %s, limit %s", elapsed, http3LoadTransferLimit))
				t.Errorf("HTTP3 download duration = %s, limit %s", elapsed, http3LoadTransferLimit)
			}
			receipt.complete()
		})
	}
}

func TestHTTP3LoadUnrelatedResponse(t *testing.T) {
	tests := map[string]struct{ size int64 }{"success: intercepted requestheaders does not hold sibling": {size: http3LoadSiblingSize}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			receipt := newLoadHTTP3Receipt(t, test.size)
			defer receipt.publish()
			entered := make(chan *flow.HTTPFlow, 1)
			observer := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				if name == "requestheaders" && f.Request.Path == "/paused" {
					f.Intercept()
					entered <- f
				}
			}}
			s := newLoadHTTP3Session(t, observer, receipt)
			paused := s.request(t, "/paused", false)
			defer func() {
				receipt.publish()
				paused.CancelRead(0x10c)
				paused.CancelWrite(0x10c)
			}()
			var intercepted *flow.HTTPFlow
			select {
			case intercepted = <-entered:
			case <-time.After(layertest.Timeout):
				receipt.fail("interception-wait", errors.New("operation did not complete"))
				buf := make([]byte, 1<<20)
				n := runtime.Stack(buf, true)
				t.Fatalf("operation did not complete:\n%s", buf[:n])
			}
			t.Cleanup(func() {
				if err := s.master.Do(context.WithoutCancel(s.ctx), func(context.Context) error {
					intercepted.Resume()
					return nil
				}); err != nil {
					t.Error(err)
				}
			})
			if !intercepted.Intercepted() {
				receipt.fail("interception-validation", errors.New("requestheaders interception was not installed before the sibling"))
				t.Fatal("requestheaders interception was not installed before the sibling")
			}
			started := time.Now()
			receipt.started.Store(&started)
			request := s.request(t, "/small", true)
			if err := request.SetReadDeadline(started.Add(http3LoadSiblingLimit)); err != nil {
				receipt.fail("read-deadline", err)
				t.Fatal(err)
			}
			readLoadHTTP3Body(t, request, test.size, receipt)
			elapsed := receipt.freezeElapsed()
			t.Logf("HTTP3 intercepted sibling response: bytes=%d duration=%s duration_ns=%d limit=%s", test.size, elapsed, elapsed.Nanoseconds(), http3LoadSiblingLimit)
			if err := s.master.Do(s.ctx, func(context.Context) error {
				if !intercepted.Intercepted() || !intercepted.Live || intercepted.Error != nil {
					return fmt.Errorf("held request changed during sibling response: intercepted=%t live=%t error=%v", intercepted.Intercepted(), intercepted.Live, intercepted.Error)
				}
				return nil
			}); err != nil {
				receipt.fail("sibling-state", err)
				t.Fatal(err)
			}
			if elapsed > http3LoadSiblingLimit {
				receipt.fail("elapsed-limit", fmt.Errorf("HTTP3 unrelated response duration = %s, limit %s", elapsed, http3LoadSiblingLimit))
				t.Errorf("HTTP3 unrelated response duration = %s, limit %s", elapsed, http3LoadSiblingLimit)
			}
			receipt.complete()
		})
	}
}
