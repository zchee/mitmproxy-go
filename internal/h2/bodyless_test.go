// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestResponseBodyLength(t *testing.T) {
	tests := map[string]struct {
		method  string
		status  string
		interim bool
		body    string
		reset   bool
	}{
		"success: HEAD representation length":                          {method: "HEAD", status: "200"},
		"success: not modified representation length":                  {method: "GET", status: "304"},
		"success: no content":                                          {method: "GET", status: "204"},
		"success: informational length does not affect final response": {method: "GET", status: "200", interim: true, body: "body"},
		"error: GET length mismatch":                                   {method: "GET", status: "200", reset: true},
		"error: HEAD DATA":                                             {method: "HEAD", status: "200", body: "body", reset: true},
		"error: no content DATA":                                       {method: "GET", status: "204", body: "body", reset: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newPipePeer(t, Config{Client: true})
			p.settings(t)
			id, err := p.endpoint.OpenStream(p.ctx)
			if err != nil {
				t.Fatal(err)
			}
			fields := requestFields()
			fields[0].Value = test.method
			if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: id, Headers: fields, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			sibling, err := p.endpoint.OpenStream(p.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: sibling, Headers: requestFields(), EndStream: true}); err != nil {
				t.Fatal(err)
			}
			if test.interim {
				p.headers(t, id.Stream, false, []hpack.HeaderField{{Name: ":status", Value: "103"}, {Name: "content-length", Value: "100"}})
				event, err := p.endpoint.ReceiveStream(p.ctx, id)
				if err != nil || event.Kind != Informational {
					t.Fatalf("interim = %+v, %v", event, err)
				}
			}
			length := "100"
			if test.interim {
				length = "4"
			}
			response := []hpack.HeaderField{{Name: ":status", Value: test.status}, {Name: "content-length", Value: length}}
			p.headers(t, id.Stream, test.body == "", response)
			event, err := p.endpoint.ReceiveStream(p.ctx, id)
			if test.body != "" {
				if err != nil || event.Kind != Headers {
					t.Fatalf("head = %+v, %v", event, err)
				}
				if err := p.framer.WriteData(id.Stream, true, []byte(test.body)); err != nil {
					t.Fatal(err)
				}
				event, err = p.endpoint.ReceiveStream(p.ctx, id)
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.reset {
				if event.Kind != Reset || event.Code != http2.ErrCodeProtocol {
					t.Fatalf("mismatch = %+v", event)
				}
				p.frame(t, func(f wireFrame) bool {
					if f.kind == http2.FrameGoAway {
						t.Fatal("body mismatch closed connection")
					}
					return f.kind == http2.FrameRSTStream && f.stream == id.Stream && f.code == http2.ErrCodeProtocol
				})
			} else if test.body == "" {
				if event.Kind != Headers || !event.EndStream {
					t.Fatalf("response = %+v", event)
				}
				if diff := cmp.Diff(response, event.Headers); diff != "" {
					t.Fatal(diff)
				}
			} else {
				if event.Kind != Data || !event.EndStream {
					t.Fatalf("body = %+v", event)
				}
				if diff := cmp.Diff([]byte(test.body), event.Data); diff != "" {
					t.Fatal(diff)
				}
				event.Receipt.Complete()
			}
			p.headers(t, sibling.Stream, true, []hpack.HeaderField{{Name: ":status", Value: "204"}})
			other, err := p.endpoint.ReceiveStream(p.ctx, sibling)
			if err != nil || other.Kind != Headers || !other.EndStream {
				t.Fatalf("sibling = %+v, %v", other, err)
			}
		})
	}
}
