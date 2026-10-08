// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"errors"
	"strings"
	"testing"

	"github.com/quic-go/qpack"
	quic "github.com/quic-go/quic-go"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h3"
)

func TestHTTP3SendFailureDiagnostic(t *testing.T) {
	tests := map[string]struct {
		code h3.ErrorCode
		want ErrorCode
	}{
		"cancel":           {code: h3.ErrCodeRequestCancelled, want: Cancel},
		"version fallback": {code: h3.ErrCodeVersionFallback, want: HTTP11Required},
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
			if err := endpoint.Send(ctx, ResponseHeaders{ID: 1, Response: &httpmsg.Response{StatusCode: 200}}); err != nil {
				t.Fatal(err)
			}
			readHTTP3TestHeaders(t, wire)
			wire.CancelRead(quic.StreamErrorCode(test.code))
			select {
			case <-endpoint.failureDone:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			err = endpoint.Send(ctx, ResponseData{ID: 1, Data: []byte("pending response")})
			failure, ok := errors.AsType[*h3.StreamError](err)
			if !ok || failure.Code != test.code || httpStreamFailure(err, GenericClientError) != test.want {
				t.Fatalf("send failure = %v; want typed %s", err, test.code)
			}
			if !strings.HasPrefix(err.Error(), "stream closed by client ("+test.code.String()+")") {
				t.Fatalf("send acknowledgement lost canonical label: %v", err)
			}
		})
	}
}
