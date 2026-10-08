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
}

func newLoadHTTP3Session(t *testing.T, observer *streamAddon) *loadHTTP3Session {
	t.Helper()
	if os.Getenv("MITMPROXY_GO_HTTP2_LOAD") != "1" {
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
		t.Fatal(err)
	}
	originListener, target := newHTTP3RoutingListener(t)
	handler, err := proxy.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mode, err := modespec.Parse("reverse:http3://" + target.String())
	if err != nil {
		t.Fatal(err)
	}
	instance, err := modeserver.New(mode, modeserver.Config{Handler: handler, ListenHost: "127.0.0.1", ListenPort: new(0), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(ctx); err != nil {
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
		t.Fatalf("reverse HTTP3 listener addresses = %v, want one UDP listener", addresses)
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		origin, err := originListener.Accept(ctx)
		if err != nil {
			if ctx.Err() == nil {
				t.Errorf("accept HTTP3 origin: %v", err)
			}
			return
		}
		defer func() { _ = origin.CloseWithError(0x100, "") }()
		stop := context.AfterFunc(ctx, func() { _ = origin.CloseWithError(0x100, "") })
		defer stop()
		startHTTP3RoutingPeer(t, ctx, origin)
		chunk := make([]byte, http3LoadChunkSize)
		for {
			request, err := origin.AcceptStream(ctx)
			if err != nil {
				if ctx.Err() == nil {
					t.Errorf("accept HTTP3 request: %v", err)
				}
				return
			}
			workers.Go(func() {
				fields, body, trailers := readHTTP3TestMessage(t, request)
				if len(body) != 0 || len(trailers) != 0 {
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
					t.Errorf("unexpected HTTP3 origin request path %q", path)
					return
				}
				writeHTTP3TestHeaders(t, request, []qpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-length", Value: strconv.FormatInt(size, 10)}})
				for remaining := size; remaining > 0; {
					n := min(remaining, int64(len(chunk)))
					writeHTTP3TestFrame(t, request, 0, chunk[:n])
					remaining -= n
				}
				if err := request.Close(); err != nil && ctx.Err() == nil {
					t.Errorf("close HTTP3 response: %v", err)
				}
			})
		}
	})
	t.Cleanup(func() { cancel(); workers.Wait() })
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	transport := &quic.Transport{Conn: socket}
	t.Cleanup(func() { _ = transport.Close() })
	address, err := net.ResolveUDPAddr("udp4", addresses[0].String())
	if err != nil {
		t.Fatal(err)
	}
	client, err := transport.Dial(ctx, address, &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, ServerName: "localhost", InsecureSkipVerify: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	startHTTP3RoutingPeer(t, ctx, client)
	s := &loadHTTP3Session{ctx: ctx, client: client, master: m, authority: target.String()}
	readLoadHTTP3Body(t, s.request(t, "/warm", true), http3LoadChunkSize)
	return s
}

func (s *loadHTTP3Session) request(t *testing.T, path string, end bool) *quic.Stream {
	t.Helper()
	stream, err := s.client.OpenStreamSync(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	writeHTTP3TestHeaders(t, stream, []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: s.authority}, {Name: ":path", Value: path}})
	if end {
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return stream
}

// Retain only a framing buffer, so the client does not accumulate the download.
func readLoadHTTP3Body(t *testing.T, stream *quic.Stream, size int64) {
	t.Helper()
	want := []qpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-length", Value: strconv.FormatInt(size, 10)}}
	if diff := gocmp.Diff(want, readHTTP3TestHeaders(t, stream)); diff != "" {
		t.Fatalf("HTTP3 response headers (-want +got):\n%s", diff)
	}
	reader := quicvarint.NewReader(stream)
	buffer := make([]byte, http3LoadChunkSize)
	var received int64
	for {
		kind, err := quicvarint.Read(reader)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		length, err := quicvarint.Read(reader)
		if err != nil || kind != 0 || length > uint64(size-received) {
			t.Fatalf("HTTP3 response frame kind=%d length=%d received=%d error=%v", kind, length, received, err)
		}
		for remaining := int64(length); remaining > 0; {
			n := min(remaining, int64(len(buffer)))
			if _, err := io.ReadFull(reader, buffer[:n]); err != nil {
				t.Fatal(err)
			}
			if bytes.Count(buffer[:n], []byte{0}) != int(n) {
				t.Fatal("HTTP3 response body differs from origin payload")
			}
			received += n
			remaining -= n
		}
	}
	if received != size {
		t.Fatalf("HTTP3 response bytes = %d, want %d", received, size)
	}
}

func TestHTTP3LoadLargeTransfer(t *testing.T) {
	tests := map[string]struct{ size int64 }{"success: 64 MiB download through reverse HTTP3": {size: loadBodySize}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			s := newLoadHTTP3Session(t, new(streamAddon))
			started := time.Now()
			request := s.request(t, "/download", true)
			if err := request.SetReadDeadline(started.Add(http3LoadTransferLimit)); err != nil {
				t.Fatal(err)
			}
			readLoadHTTP3Body(t, request, test.size)
			elapsed := time.Since(started)
			t.Logf("HTTP3 reverse download: bytes=%d duration=%s duration_ns=%d limit=%s", test.size, elapsed, elapsed.Nanoseconds(), http3LoadTransferLimit)
			if elapsed > http3LoadTransferLimit {
				t.Errorf("HTTP3 download duration = %s, limit %s", elapsed, http3LoadTransferLimit)
			}
		})
	}
}

func TestHTTP3LoadUnrelatedResponse(t *testing.T) {
	tests := map[string]struct{ size int64 }{"success: intercepted requestheaders does not hold sibling": {size: http3LoadSiblingSize}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			entered := make(chan *flow.HTTPFlow, 1)
			observer := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				if name == "requestheaders" && f.Request.Path == "/paused" {
					f.Intercept()
					entered <- f
				}
			}}
			s := newLoadHTTP3Session(t, observer)
			paused := s.request(t, "/paused", false)
			defer paused.CancelRead(0x10c)
			defer paused.CancelWrite(0x10c)
			intercepted := await(t, entered)
			t.Cleanup(func() {
				if err := s.master.Do(context.WithoutCancel(s.ctx), func(context.Context) error {
					intercepted.Resume()
					return nil
				}); err != nil {
					t.Error(err)
				}
			})
			if !intercepted.Intercepted() {
				t.Fatal("requestheaders interception was not installed before the sibling")
			}
			started := time.Now()
			request := s.request(t, "/small", true)
			if err := request.SetReadDeadline(started.Add(http3LoadSiblingLimit)); err != nil {
				t.Fatal(err)
			}
			readLoadHTTP3Body(t, request, test.size)
			elapsed := time.Since(started)
			t.Logf("HTTP3 intercepted sibling response: bytes=%d duration=%s duration_ns=%d limit=%s", test.size, elapsed, elapsed.Nanoseconds(), http3LoadSiblingLimit)
			if err := s.master.Do(s.ctx, func(context.Context) error {
				if !intercepted.Intercepted() || !intercepted.Live || intercepted.Error != nil {
					return fmt.Errorf("held request changed during sibling response: intercepted=%t live=%t error=%v", intercepted.Intercepted(), intercepted.Live, intercepted.Error)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if elapsed > http3LoadSiblingLimit {
				t.Errorf("HTTP3 unrelated response duration = %s, limit %s", elapsed, http3LoadSiblingLimit)
			}
		})
	}
}
