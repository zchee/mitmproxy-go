// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestGoAwayStreamInitiator(t *testing.T) {
	roles := map[string]struct{ client bool }{"client": {client: true}, "server": {}}
	for role, config := range roles {
		t.Run(role, func(t *testing.T) {
			tests := map[string]struct {
				last uint32
				code http2.ErrCode
			}{
				"success: accepted stream completes":                {last: 1},
				"success: threshold applies only to local streams":  {},
				"error: failure GOAWAY terminates either initiator": {code: http2.ErrCodeProtocol},
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
					failed := p.endpoint.StreamFailed(id)
					if err := p.framer.WriteGoAway(test.last, test.code, nil); err != nil {
						t.Fatal(err)
					}
					away, err := p.endpoint.Receive(p.ctx)
					if err != nil || away.Kind != GoAway {
						t.Fatalf("GOAWAY = %+v, %v", away, err)
					}
					wantFailure := test.code != http2.ErrCodeNo || config.client && id.Stream > test.last
					if wantFailure {
						reset, err := p.endpoint.ReceiveStream(p.ctx, id)
						if err == nil {
							err = reset.Err
						}
						failure, ok := errors.AsType[*StreamError](err)
						if !ok {
							t.Fatalf("GOAWAY stream = %+v, %v", reset, err)
						}
						if diff := gocmp.Diff(test.code, failure.Code); diff != "" {
							t.Fatal(diff)
						}
						select {
						case <-failed:
						default:
							t.Fatal("failed stream did not release its observer")
						}
						return
					}
					select {
					case <-failed:
						t.Fatal("GOAWAY excluded a peer-initiated or accepted stream")
					default:
					}
					fields := []hpack.HeaderField{{Name: ":status", Value: "204"}}
					if config.client {
						p.headers(t, id.Stream, true, fields)
						head, err := p.endpoint.ReceiveStream(p.ctx, id)
						if err != nil || head.Kind != Headers || !head.EndStream {
							t.Fatalf("accepted response = %+v, %v", head, err)
						}
					} else if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: id, Headers: fields, EndStream: true}); err != nil {
						t.Fatal(err)
					}
					select {
					case <-failed:
						t.Fatal("normal completion signalled failure")
					default:
					}
				})
			}
		})
	}
}
