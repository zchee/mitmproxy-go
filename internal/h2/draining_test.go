// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestOpenStreamDraining(t *testing.T) {
	roles := map[string]struct{ client bool }{"client": {client: true}, "server": {}}
	for role, config := range roles {
		t.Run(role, func(t *testing.T) {
			tests := map[string]struct{ code http2.ErrCode }{
				"success: graceful drain": {code: http2.ErrCodeNo},
				"error: protocol GOAWAY":  {code: http2.ErrCodeProtocol},
			}
			for name, test := range tests {
				t.Run(name, func(t *testing.T) {
					p := newPipePeer(t, Config{Client: config.client})
					p.settings(t)
					var id layer.StreamIdentity
					if config.client {
						var err error
						id, err = p.endpoint.OpenStream(p.ctx)
						if err != nil {
							t.Fatal(err)
						}
						if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: id, Headers: requestFields(), EndStream: true}); err != nil {
							t.Fatal(err)
						}
					} else {
						p.headers(t, 1, true, requestFields())
						head, err := p.endpoint.Receive(p.ctx)
						if err != nil {
							t.Fatal(err)
						}
						id = head.Identity
					}
					if err := p.framer.WriteGoAway(0x7fffffff, test.code, nil); err != nil {
						t.Fatal(err)
					}
					away, err := p.endpoint.Receive(p.ctx)
					if err != nil || away.Kind != GoAway {
						t.Fatalf("GOAWAY = %+v, %v", away, err)
					}
					_, err = p.endpoint.OpenStream(p.ctx)
					if !errors.Is(err, ErrDraining) {
						t.Fatalf("OpenStream after GOAWAY = %v", err)
					}
					if test.code == http2.ErrCodeNo {
						fields := []hpack.HeaderField{{Name: ":status", Value: "200"}}
						if config.client {
							p.headers(t, uint32(id.Stream), false, fields)
							if err := p.framer.WriteData(uint32(id.Stream), true, []byte("accepted")); err != nil {
								t.Fatal(err)
							}
							head, err := p.endpoint.ReceiveStream(p.ctx, id)
							if err != nil || head.Kind != Headers {
								t.Fatalf("accepted headers = %+v, %v", head, err)
							}
							body, err := p.endpoint.ReceiveStream(p.ctx, id)
							if err != nil {
								t.Fatal(err)
							}
							if diff := gocmp.Diff("accepted", string(body.Data)); diff != "" {
								t.Fatal(diff)
							}
							body.Receipt.Complete()
						} else if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: id, Headers: fields, EndStream: true}); err != nil {
							t.Fatal(err)
						}
					} else {
						reset, err := p.endpoint.ReceiveStream(p.ctx, id)
						if err == nil {
							err = reset.Err
						}
						failure, ok := errors.AsType[*StreamError](err)
						if !ok || failure.Code != test.code {
							t.Fatalf("error GOAWAY stream = %+v, %v", reset, err)
						}
					}
					select {
					case <-p.endpoint.Done():
					case <-p.ctx.Done():
						t.Fatal("drained endpoint did not stop")
					}
					if _, err := p.endpoint.OpenStream(p.ctx); !errors.Is(err, ErrDraining) {
						t.Fatalf("OpenStream after drain = %v", err)
					}
					if _, err := p.endpoint.Receive(p.ctx); !errors.Is(err, io.EOF) {
						t.Fatalf("Receive after drain = %v", err)
					}
				})
			}
		})
	}
}
