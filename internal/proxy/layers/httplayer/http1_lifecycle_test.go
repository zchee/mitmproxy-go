// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func TestHTTP1ResponseFidelityAfterReceiveCompletes(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		raw   string
		want  string
		count uint64
	}{
		"success: spacing and duplicate fields survive completion": {
			raw:  "HTTP/1.1 200  OK\r\nX-Foo:  one\r\nx-foo:\ttwo\r\nContent-Length: 0\r\n\r\n",
			want: "HTTP/1.1 200  OK\r\nX-Foo:  one\r\nx-foo:\ttwo\r\nContent-Length: 0\r\n\r\n",
		},
		"success: folded response counts at emission": {
			raw:   "HTTP/1.1 200 OK\r\nX-Foo: one\r\n\ttwo\r\nContent-Length: 0\r\n\r\n",
			want:  "HTTP/1.1 200 OK\r\nX-Foo: one\r\n two\r\nContent-Length: 0\r\n\r\n",
			count: 1,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			clientConn, clientPeer := layertest.Pipe(t)
			serverConn, serverPeer := layertest.Pipe(t)
			store := newWireStore()
			counter := &http1.FidelityCounter{}
			client := newHTTP1Server(clientConn, store, counter)
			server := newHTTP1Client(serverConn, store, counter)
			ctx := t.Context()
			writeAll(t, clientPeer, "GET / HTTP/1.1\r\n\r\n")
			for range 2 {
				event, err := client.Receive(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := server.Send(ctx, event); err != nil {
					t.Fatal(err)
				}
			}
			writeAll(t, serverPeer, tt.raw)
			head, err := server.Receive(ctx)
			if err != nil {
				t.Fatal(err)
			}
			end, err := server.Receive(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := end.(ResponseEndOfMessage); !ok {
				t.Fatalf("Receive() = %T, want response end", end)
			}
			if err := serverPeer.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if _, err := server.Receive(ctx); !errors.Is(err, io.EOF) {
				t.Fatalf("Receive() after FIN = %v", err)
			}
			for _, event := range []ResponseEvent{head, end} {
				if err := client.Send(ctx, event); err != nil {
					t.Fatal(err)
				}
			}
			if err := clientConn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, readToEOF(t, clientPeer)); diff != "" {
				t.Fatalf("response wire differs (-want +got):\n%s", diff)
			}
			if got := counter.Load(); got != tt.count {
				t.Fatalf("fidelity = %d, want %d", got, tt.count)
			}
		})
	}
}

func TestHTTP1SendRetainsOwnedTrailers(t *testing.T) {
	t.Parallel()
	tests := map[string]struct{ response bool }{
		"success: response trailers": {response: true},
		"success: request trailers":  {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			conn, peer := layertest.Pipe(t)
			ctx := t.Context()
			trailers := httpmsg.Headers{{Name: []byte("X-T"), Value: []byte("original")}}
			headers := httpmsg.Headers{{Name: []byte("Transfer-Encoding"), Value: []byte("chunked")}}
			var end func() error
			var want string
			if tt.response {
				endpoint := newHTTP1Server(conn, newWireStore(), nil)
				writeAll(t, peer, "GET / HTTP/1.1\r\n\r\n")
				for range 2 {
					if _, err := endpoint.Receive(ctx); err != nil {
						t.Fatal(err)
					}
				}
				response := &httpmsg.Response{HTTPVersion: "HTTP/1.1", Headers: headers, StatusCode: 200, Reason: "OK"}
				if err := endpoint.Send(ctx, ResponseHeaders{ID: 1, Response: response}); err != nil {
					t.Fatal(err)
				}
				if err := endpoint.Send(ctx, ResponseTrailers{ID: 1, Trailers: trailers}); err != nil {
					t.Fatal(err)
				}
				want = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-T: original\r\n\r\n"
				end = func() error { return endpoint.Send(ctx, ResponseEndOfMessage{ID: 1}) }
			} else {
				endpoint := newHTTP1Client(conn, newWireStore(), nil)
				request := &httpmsg.Request{Method: "POST", Path: "/", HTTPVersion: "HTTP/1.1", Headers: headers}
				if err := endpoint.Send(ctx, RequestHeaders{ID: 1, Request: request}); err != nil {
					t.Fatal(err)
				}
				if err := endpoint.Send(ctx, RequestTrailers{ID: 1, Trailers: trailers}); err != nil {
					t.Fatal(err)
				}
				want = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-T: original\r\n\r\n"
				end = func() error { return endpoint.Send(ctx, RequestEndOfMessage{ID: 1}) }
			}
			copy(trailers[0].Value, "modified")
			if err := end(); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(want, readExactly(t, peer, len(want))); diff != "" {
				t.Fatalf("trailer ownership differs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHTTP1CanceledSendDoesNotMutateExchange(t *testing.T) {
	t.Parallel()
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Client(conn, newWireStore(), nil)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	head := RequestHeaders{ID: 1, Request: mustRequest(t, "GET", "http://example.com/", nil)}
	if err := endpoint.Send(ctx, head); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Send() = %v, want context.Canceled", err)
	}
	if err := endpoint.Send(t.Context(), head); err != nil {
		t.Fatalf("Send() after cancellation = %v", err)
	}
	want := "GET / HTTP/1.1\r\ncontent-length: 0\r\n\r\n"
	if got := readExactly(t, peer, len(want)); got != want {
		t.Fatalf("request = %q, want %q", got, want)
	}
}
