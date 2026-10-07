// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"net"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestStreamDone(t *testing.T) {
	tests := map[string]struct{ termination string }{
		"success: peer reset without receiving":      {termination: "reset"},
		"success: repeated local cancellation":       {termination: "cancel"},
		"success: GOAWAY excludes only later stream": {termination: "goaway"},
		"success: disconnect":                        {termination: "disconnect"},
		"success: normal completion":                 {termination: "complete"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newPipePeer(t, Config{Client: true})
			p.settings(t, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0})
			id, err := p.endpoint.OpenStream(p.ctx)
			if err != nil {
				t.Fatal(err)
			}
			other, err := p.endpoint.OpenStream(p.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if test.termination == "goaway" {
				id, other = other, id
				if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: other, Headers: requestFields()}); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: id, Headers: requestFields(), EndStream: test.termination == "complete"}); err != nil {
				t.Fatal(err)
			}
			done := p.endpoint.StreamDone(id)
			if done != p.endpoint.StreamDone(id) {
				t.Fatal("live stream channel changed")
			}
			select {
			case <-done:
				t.Fatal("live stream already terminated")
			default:
			}
			otherDone := p.endpoint.StreamDone(other)
			var credit *request
			if test.termination != "complete" {
				credit = newRequest(p.ctx, waitSendCredit)
				credit.id = id
				p.endpoint.requests <- credit
			}
			switch test.termination {
			case "reset":
				if err := p.framer.WriteRSTStream(id.Stream, http2.ErrCodeCancel); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				for range 2 {
					if err := p.endpoint.CancelStream(id, http2.ErrCodeCancel); err != nil {
						t.Fatal(err)
					}
				}
			case "goaway":
				if err := p.framer.WriteGoAway(other.Stream, http2.ErrCodeNo, nil); err != nil {
					t.Fatal(err)
				}
			case "disconnect":
				if err := p.conn.Close(); err != nil {
					t.Fatal(err)
				}
			case "complete":
				p.headers(t, id.Stream, true, []hpack.HeaderField{{Name: ":status", Value: "200"}})
			}
			select {
			case <-done:
			case <-p.ctx.Done():
				t.Fatal("stream termination not observed")
			}
			select {
			case <-p.endpoint.StreamDone(id):
			default:
				t.Fatal("terminated stream channel reopened")
			}
			if credit != nil {
				select {
				case result := <-credit.result:
					if result.err == nil {
						t.Fatal("terminated stream granted credit")
					}
				case <-p.ctx.Done():
					t.Fatal("credit waiter survived termination")
				}
			}
			if test.termination != "disconnect" {
				select {
				case <-otherDone:
					t.Fatal("unaffected stream terminated")
				default:
				}
				event, err := p.endpoint.ReceiveStream(p.ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				want := Reset
				if test.termination == "complete" {
					want = Headers
				}
				if event.Kind != want {
					t.Fatalf("termination observation consumed event: %+v", event)
				}
			} else {
				select {
				case <-otherDone:
				case <-p.ctx.Done():
					t.Fatal("disconnect left another stream live")
				}
			}
			for _, unknown := range []layer.StreamIdentity{{Endpoint: id.Endpoint, Stream: 99}, {Endpoint: "foreign", Stream: id.Stream}} {
				select {
				case <-p.endpoint.StreamDone(unknown):
				default:
					t.Fatalf("unknown identity remains live: %+v", unknown)
				}
			}
		})
	}
}

func TestStreamDoneBeforeRun(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = conn.Close(); _ = peer.Close() }()
	e, err := New(conn, Config{Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-e.StreamDone(layer.StreamIdentity{Endpoint: "endpoint", Stream: 1}):
	default:
		t.Fatal("unknown stream before Run remains live")
	}
}
