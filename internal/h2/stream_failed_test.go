// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestStreamFailed(t *testing.T) {
	roles := map[string]struct{ client bool }{"client": {client: true}, "server": {}}
	for role, config := range roles {
		t.Run(role, func(t *testing.T) {
			tests := map[string]struct{ termination string }{
				"success: completion does not fail": {termination: "complete"},
				"error: reset":                      {termination: "reset"},
				"error: cancellation":               {termination: "cancel"},
				"error: GOAWAY":                     {termination: "goaway"},
				"error: disconnect":                 {termination: "disconnect"},
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
					done := p.endpoint.StreamDone(id)
					if failed != p.endpoint.StreamFailed(id) {
						t.Fatal("failure channel changed")
					}
					select {
					case <-failed:
						t.Fatal("live stream failed")
					default:
					}
					switch test.termination {
					case "complete":
						fields := []hpack.HeaderField{{Name: ":status", Value: "204"}}
						if config.client {
							p.headers(t, id.Stream, true, fields)
						} else if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: id, Headers: fields, EndStream: true}); err != nil {
							t.Fatal(err)
						}
					case "reset":
						if err := p.framer.WriteRSTStream(id.Stream, http2.ErrCodeCancel); err != nil {
							t.Fatal(err)
						}
					case "cancel":
						if err := p.endpoint.CancelStream(id, http2.ErrCodeCancel); err != nil {
							t.Fatal(err)
						}
					case "goaway":
						if err := p.framer.WriteGoAway(0, http2.ErrCodeProtocol, nil); err != nil {
							t.Fatal(err)
						}
					case "disconnect":
						if err := p.conn.Close(); err != nil {
							t.Fatal(err)
						}
					}
					select {
					case <-done:
					case <-p.ctx.Done():
						t.Fatal("termination not observed")
					}
					if test.termination == "complete" {
						select {
						case <-failed:
							t.Fatal("successful stream failed")
						default:
						}
					} else {
						select {
						case <-failed:
						case <-p.ctx.Done():
							t.Fatal("failure not observed")
						}
					}
					for _, unknown := range []layer.StreamIdentity{{Endpoint: id.Endpoint, Stream: 99}, {Endpoint: "foreign", Stream: id.Stream}} {
						select {
						case <-p.endpoint.StreamFailed(unknown):
						default:
							t.Fatalf("unknown stream remains live: %+v", unknown)
						}
					}
				})
			}
		})
	}
}
