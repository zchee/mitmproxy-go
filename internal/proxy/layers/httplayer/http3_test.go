// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"runtime/pprof"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/quic-go/qpack"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h3"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// Frame-level peers deliberately do not use the engine under test to encode
// their messages. Static QPACK matches the advertised zero dynamic capacity.
type http3TestPeer struct {
	conn *quic.Conn
}

func http3TestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(finished)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			var stacks bytes.Buffer
			_ = pprof.Lookup("goroutine").WriteTo(&stacks, 2)
			t.Errorf("HTTP/3 lifecycle watchdog:\n%s", stacks.String())
		}
	})
	t.Cleanup(func() {
		if !stop() {
			<-finished
		}
		cancel()
	})
	return ctx
}

func newHTTP3TestPeer(t *testing.T, ctx context.Context, engineClient bool) (*http3TestPeer, *h3.Endpoint) {
	t.Helper()
	key, ca, err := certs.CreateCA("HTTP3 adapter", "HTTP3 adapter root", 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certs.DummyCert(key, ca, "localhost", []certs.GeneralName{certs.DNSName("localhost")}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.X509())
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.X509().Raw, ca.X509().Raw}, PrivateKey: key}}}
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, RootCAs: roots, ServerName: "localhost"}
	serverSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSocket.Close() })
	serverTransport := &quic.Transport{Conn: serverSocket}
	t.Cleanup(func() { _ = serverTransport.Close() })
	listener, err := serverTransport.Listen(serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	clientSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientSocket.Close() })
	clientTransport := &quic.Transport{Conn: clientSocket}
	t.Cleanup(func() { _ = clientTransport.Close() })
	client, err := clientTransport.Dial(ctx, serverSocket.LocalAddr(), clientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0x100, "") })
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.CloseWithError(0x100, "") })
	peerConn, engineConn := client, server
	if engineClient {
		peerConn, engineConn = server, client
	}
	endpoint, err := h3.New(engineConn, h3.Config{Descriptor: layer.EndpointDescriptor{Identity: "adapter", Protocol: "h3", FromClient: !engineClient}, Client: engineClient, ValidateInboundHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	workers.Go(func() { _ = endpoint.Run(runCtx) })
	workers.Go(func() {
		for {
			stream, err := peerConn.AcceptUniStream(runCtx)
			if err != nil {
				return
			}
			workers.Go(func() { _, _ = io.Copy(io.Discard, stream) })
		}
	})
	t.Cleanup(func() {
		cancel()
		_ = peerConn.CloseWithError(0x100, "")
		workers.Wait()
	})
	for _, streamType := range []uint64{0, 2, 3} {
		stream, err := peerConn.OpenUniStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		data := quicvarint.Append(nil, streamType)
		if streamType == 0 {
			// SETTINGS with QPACK capacity and blocked streams both zero.
			data = append(data, 4, 4, 1, 0, 7, 0)
		}
		if _, err := stream.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	return &http3TestPeer{conn: peerConn}, endpoint
}

func writeHTTP3TestFrame(t *testing.T, writer io.Writer, kind uint64, payload []byte) {
	t.Helper()
	frame := quicvarint.Append(nil, kind)
	frame = quicvarint.Append(frame, uint64(len(payload)))
	frame = append(frame, payload...)
	if _, err := writer.Write(frame); err != nil {
		t.Fatal(err)
	}
}

func writeHTTP3TestHeaders(t *testing.T, writer io.Writer, fields []qpack.HeaderField) {
	t.Helper()
	var block bytes.Buffer
	encoder := qpack.NewEncoder(&block)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	writeHTTP3TestFrame(t, writer, 1, block.Bytes())
}

func readHTTP3TestFrame(t *testing.T, reader io.Reader) (uint64, []byte) {
	t.Helper()
	kind, err := quicvarint.Read(quicvarint.NewReader(reader))
	if err != nil {
		t.Fatal(err)
	}
	length, err := quicvarint.Read(quicvarint.NewReader(reader))
	if err != nil || length > h3.MaxHeaderBytes {
		t.Fatalf("frame length = %d, error = %v", length, err)
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatal(err)
	}
	return kind, payload
}

func readHTTP3TestHeaders(t *testing.T, reader io.Reader) []qpack.HeaderField {
	t.Helper()
	kind, block := readHTTP3TestFrame(t, reader)
	if kind != 1 {
		t.Fatalf("frame kind = %d, want HEADERS", kind)
	}
	decode := qpack.NewDecoder().Decode(block)
	var fields []qpack.HeaderField
	for {
		field, err := decode()
		if errors.Is(err, io.EOF) {
			return fields
		}
		if err != nil {
			t.Fatal(err)
		}
		fields = append(fields, field)
	}
}

func TestHTTP3AdapterRequestEvents(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	// py:test/mitmproxy/proxy/layers/http/test_http3.py:test_request_trailers.
	tests := map[string]struct {
		grease bool
	}{"ordered request and delayed trailers FIN": {}, "GREASE frame and stream preserve request": {grease: true}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			peer, engine := newHTTP3TestPeer(t, ctx, false)
			if test.grease {
				uni, err := peer.conn.OpenUniStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := uni.Write(quicvarint.Append(nil, 0x21)); err != nil {
					t.Fatal(err)
				}
				if err := uni.Close(); err != nil {
					t.Fatal(err)
				}
			}
			wire, err := peer.conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if test.grease {
				writeHTTP3TestFrame(t, wire, 0x21, []byte("ignored"))
			}
			fields := []qpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: "example.com"}, {Name: "x-foo", Value: "1"}, {Name: "x-bar", Value: "2"}, {Name: "x-foo", Value: "3"}}
			writeHTTP3TestHeaders(t, wire, fields)
			head, err := engine.Receive(ctx)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := &http3Server{engine: engine, identity: head.Identity, failureDone: engine.StreamFailed(head.Identity), id: 37, head: &head}
			event, err := endpoint.Receive(ctx)
			request, ok := event.(RequestHeaders)
			if err != nil || !ok {
				t.Fatalf("head = %T, error = %v", event, err)
			}
			if request.Request.HTTPVersion != "HTTP/3" || request.ID != 37 || request.EndStream {
				t.Fatalf("request = %+v", request)
			}
			want := httpmsg.Headers{{Name: []byte("x-foo"), Value: []byte("1")}, {Name: []byte("x-bar"), Value: []byte("2")}, {Name: []byte("x-foo"), Value: []byte("3")}}
			if diff := gocmp.Diff(want, request.Request.Headers); diff != "" {
				t.Fatal(diff)
			}
			writeHTTP3TestFrame(t, wire, 0, []byte("Hello World!"))
			event, err = endpoint.Receive(ctx)
			data, ok := event.(RequestData)
			if err != nil || !ok || string(data.Data) != "Hello World!" {
				t.Fatalf("DATA = %+v, error = %v", event, err)
			}
			receipt := endpoint.takeReceipt()
			if receipt == nil || receipt.OriginalBytes() != len(data.Data) {
				t.Fatalf("receipt = %v", receipt)
			}
			receipt.Complete()
			trailers := []qpack.HeaderField{{Name: "req-trailer-a", Value: "a"}, {Name: "req-trailer-b", Value: "b"}}
			writeHTTP3TestHeaders(t, wire, trailers)
			event, err = endpoint.Receive(ctx)
			if _, ok := event.(RequestTrailers); err != nil || !ok {
				t.Fatalf("trailers = %T, error = %v", event, err)
			}
			if endpoint.receivedEnd || len(endpoint.queue) != 0 {
				t.Fatal("trailers synthesized completion before FIN")
			}
			if err := wire.Close(); err != nil {
				t.Fatal(err)
			}
			event, err = endpoint.Receive(ctx)
			if _, ok := event.(RequestEndOfMessage); err != nil || !ok {
				t.Fatalf("EOF = %T, error = %v", event, err)
			}
			if endpoint.takeReceipt() != nil {
				t.Fatal("zero-byte EOF receipt escaped adapter")
			}
		})
	}
}

func TestHTTP3AdapterResponseEvents(t *testing.T) {
	// py:test/mitmproxy/proxy/layers/http/test_http3.py:test_simple, test_response_trailers.
	tests := map[string]struct{ informational bool }{"final response and trailers": {}, "informational before final": {informational: true}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			peer, engine := newHTTP3TestPeer(t, ctx, true)
			id, err := engine.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := &http3Client{engine: engine, identity: id, failureDone: engine.StreamFailed(id), id: 91, normalize: true}
			request := &httpmsg.Request{Method: "GET", Scheme: "https", Authority: "example.com", Host: "example.com", Port: 443, Path: "/", HTTPVersion: "HTTP/3"}
			if err := endpoint.Send(ctx, RequestHeaders{ID: 91, Request: request, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			wire, err := peer.conn.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_ = readHTTP3TestHeaders(t, wire)
			if test.informational {
				writeHTTP3TestHeaders(t, wire, []qpack.HeaderField{{Name: ":status", Value: "103"}})
			}
			writeHTTP3TestHeaders(t, wire, []qpack.HeaderField{{Name: ":status", Value: "200"}})
			event, err := endpoint.Receive(ctx)
			response, ok := event.(ResponseHeaders)
			if err != nil || !ok || response.Response.HTTPVersion != "HTTP/3" || response.Response.StatusCode != 200 || response.ID != 91 {
				t.Fatalf("response = %+v, error = %v", event, err)
			}
			writeHTTP3TestFrame(t, wire, 0, []byte("Hello, World!"))
			event, err = endpoint.Receive(ctx)
			if data, ok := event.(ResponseData); err != nil || !ok || string(data.Data) != "Hello, World!" {
				t.Fatalf("DATA = %+v, error = %v", event, err)
			}
			endpoint.takeReceipt().Complete()
			writeHTTP3TestHeaders(t, wire, []qpack.HeaderField{{Name: "resp-trailer-a", Value: "a"}, {Name: "resp-trailer-b", Value: "b"}})
			if err := wire.Close(); err != nil {
				t.Fatal(err)
			}
			event, err = endpoint.Receive(ctx)
			if _, ok := event.(ResponseTrailers); err != nil || !ok {
				t.Fatalf("trailers = %T, error = %v", event, err)
			}
			event, err = endpoint.Receive(ctx)
			if _, ok := event.(ResponseEndOfMessage); err != nil || !ok {
				t.Fatalf("end = %T, error = %v", event, err)
			}
		})
	}
}

func TestHTTP3AdapterReset(t *testing.T) {
	// py:test/mitmproxy/proxy/layers/http/test_http3.py:test_receive_stop_sending.
	tests := map[string]struct {
		wire h3.ErrorCode
		want ErrorCode
	}{
		"cancel":           {wire: h3.ErrCodeRequestCancelled, want: Cancel},
		"version fallback": {wire: h3.ErrCodeVersionFallback, want: HTTP11Required},
		"internal":         {wire: h3.ErrCodeInternal, want: GenericClientError},
		"unknown":          {wire: 0x999, want: GenericClientError},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			peer, engine := newHTTP3TestPeer(t, ctx, false)
			wire, err := peer.conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			writeHTTP3TestHeaders(t, wire, []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}})
			head, err := engine.Receive(ctx)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := &http3Server{engine: engine, identity: head.Identity, failureDone: engine.StreamFailed(head.Identity), id: 1, head: &head}
			if _, err := endpoint.Receive(ctx); err != nil {
				t.Fatal(err)
			}
			wire.CancelWrite(quic.StreamErrorCode(test.wire))
			event, err := endpoint.Receive(ctx)
			failure, ok := event.(RequestProtocolError)
			wantMessage := "stream closed by client (" + test.wire.String() + ")"
			if err != nil || !ok || failure.Code != test.want || failure.Message != wantMessage {
				t.Fatalf("reset = %+v, error = %v; want %s", event, err, wantMessage)
			}
		})
	}
}

func TestHTTP3ResetCodes(t *testing.T) {
	tests := map[string]struct {
		input ErrorCode
		want  h3.ErrorCode
	}{
		"cancel": {Cancel, h3.ErrCodeRequestCancelled}, "disconnect": {ClientDisconnected, h3.ErrCodeRequestCancelled}, "passthrough": {PassthroughClose, h3.ErrCodeRequestCancelled}, "fallback": {HTTP11Required, h3.ErrCodeVersionFallback}, "kill": {Kill, h3.ErrCodeInternal}, "server": {GenericServerError, h3.ErrCodeInternal},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := h3ResetCode(test.input); got != test.want {
				t.Fatalf("reset = %s, want %s", got, test.want)
			}
		})
	}
}
