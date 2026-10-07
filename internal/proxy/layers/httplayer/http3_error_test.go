// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/quic-go/qpack"
	quic "github.com/quic-go/quic-go"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h3"
	"github.com/zchee/mitmproxy-go/internal/version"
)

func TestHTTP3AdapterErrorResponse(t *testing.T) {
	// py:test/mitmproxy/proxy/layers/http/test_http3.py:test_upstream_error
	// and test_fail_without_header; these exercise the response encoder only.
	tests := map[string]struct {
		code  ErrorCode
		reset h3.ErrorCode
	}{"upstream failure produces escaped 502": {code: ConnectFailed}, "kill resets before response headers": {code: Kill, reset: h3.ErrCodeInternal}, "cancel preserves wire code": {code: Cancel, reset: h3.ErrCodeRequestCancelled}, "fallback preserves wire code": {code: HTTP11Required, reset: h3.ErrCodeVersionFallback}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			peer, engine := newHTTP3TestPeer(t, ctx, false)
			wire, err := peer.conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			writeHTTP3TestHeaders(t, wire, []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: "example.com"}})
			head, err := engine.Receive(ctx)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := &http3Server{engine: engine, identity: head.Identity, failureDone: engine.StreamFailed(head.Identity), id: 1, normalize: true, head: &head}
			if _, err := endpoint.Receive(ctx); err != nil {
				t.Fatal(err)
			}
			if err := endpoint.Send(ctx, ResponseProtocolError{ID: 1, Message: "oops server <> error", Code: test.code}); err != nil {
				t.Fatal(err)
			}
			if test.reset != 0 {
				var data [1]byte
				_, err := wire.Read(data[:])
				reset, ok := errors.AsType[*quic.StreamError](err)
				if !ok || !reset.Remote || reset.ErrorCode != quic.StreamErrorCode(test.reset) {
					t.Fatalf("wire reset = %v, want %s", err, test.reset)
				}
				return
			}
			fields, body, trailers := readHTTP3TestMessage(t, wire)
			want := []qpack.HeaderField{{Name: ":status", Value: "502"}, {Name: "server", Value: version.String()}, {Name: "content-type", Value: "text/html"}}
			if diff := gocmp.Diff(want, fields); diff != "" {
				t.Fatal(diff)
			}
			if !bytes.Contains(body, []byte("502 Bad Gateway")) || !bytes.Contains(body, []byte("server &lt;&gt; error")) || len(trailers) != 0 {
				t.Fatalf("error body = %q, trailers = %v", body, trailers)
			}
		})
	}
}

func TestHTTP3AdapterInformationalSend(t *testing.T) {
	tests := map[string]struct{ status int }{"continue": {100}, "early hints": {103}}
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
			endpoint := &http3Server{engine: engine, identity: head.Identity, failureDone: engine.StreamFailed(head.Identity), id: 1, normalize: true, head: &head}
			if _, err := endpoint.Receive(ctx); err != nil {
				t.Fatal(err)
			}
			if err := endpoint.Send(ctx, ResponseHeaders{ID: 1, Response: &httpmsg.Response{HTTPVersion: "HTTP/3", StatusCode: test.status}, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			if endpoint.sentHeaders || endpoint.sentEnd {
				t.Fatal("informational response finished the message")
			}
			_ = readHTTP3TestHeaders(t, wire)
			if err := endpoint.Send(ctx, ResponseHeaders{ID: 1, Response: &httpmsg.Response{HTTPVersion: "HTTP/3", StatusCode: 204}, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			fields := readHTTP3TestHeaders(t, wire)
			if diff := gocmp.Diff([]qpack.HeaderField{{Name: ":status", Value: "204"}}, fields); diff != "" {
				t.Fatal(diff)
			}
			var data [1]byte
			if _, err := wire.Read(data[:]); !errors.Is(err, io.EOF) {
				t.Fatalf("final FIN = %v", err)
			}
		})
	}
}

func TestHTTP3AdapterBorrowedReceiptCancellation(t *testing.T) {
	tests := map[string]struct{ cancelPeer bool }{"local cancellation": {}, "peer reset": {cancelPeer: true}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			peer, engine := newHTTP3TestPeer(t, ctx, false)
			wire, err := peer.conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			writeHTTP3TestHeaders(t, wire, []qpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}})
			head, err := engine.Receive(ctx)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := &http3Server{engine: engine, identity: head.Identity, failureDone: engine.StreamFailed(head.Identity), id: 1, head: &head}
			if _, err := endpoint.Receive(ctx); err != nil {
				t.Fatal(err)
			}
			writeHTTP3TestFrame(t, wire, 0, []byte("original bytes"))
			if _, err := endpoint.Receive(ctx); err != nil {
				t.Fatal(err)
			}
			receipt := endpoint.takeReceipt()
			if test.cancelPeer {
				wire.CancelWrite(quic.StreamErrorCode(h3.ErrCodeRequestCancelled))
			} else if err := engine.CancelStream(head.Identity, h3.ErrCodeRequestCancelled); err != nil {
				t.Fatal(err)
			}
			select {
			case <-endpoint.failureDone:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if receipt.Complete() {
				t.Fatal("invalidated original bytes were consumed twice")
			}
			if _, err := endpoint.Receive(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
