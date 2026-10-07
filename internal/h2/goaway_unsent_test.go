// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"errors"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestGoAwayUnsentLowerStream(t *testing.T) {
	tests := map[string]struct {
		started bool
	}{
		"error: allocated unsent stream below GOAWAY limit": {},
		"success: wire-started stream below GOAWAY limit":   {started: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newPipePeer(t, Config{Client: true})
			p.settings(t)
			first, err := p.endpoint.OpenStream(p.ctx)
			if err != nil {
				t.Fatal(err)
			}
			later, err := p.endpoint.OpenStream(p.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: first, Headers: requestFields(), EndStream: true}); err != nil {
				t.Fatal(err)
			}
			p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameHeaders })
			if test.started {
				if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: later, Headers: requestFields(), EndStream: true}); err != nil {
					t.Fatal(err)
				}
				p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameHeaders })
			}
			failed, done := p.endpoint.StreamFailed(later), p.endpoint.StreamDone(later)
			if err := p.framer.WriteGoAway(later.Stream, http2.ErrCodeNo, nil); err != nil {
				t.Fatal(err)
			}
			away, err := p.endpoint.Receive(p.ctx)
			if err != nil || away.Kind != GoAway {
				t.Fatalf("GOAWAY = %+v, %v", away, err)
			}
			for _, signal := range []<-chan struct{}{failed, done} {
				select {
				case <-signal:
					if test.started {
						t.Fatal("GOAWAY failed an accepted wire-started stream")
					}
				default:
					if !test.started {
						t.Fatal("GOAWAY retained an unsent stream below its last-stream limit")
					}
				}
			}
			if !test.started {
				err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: later, Headers: requestFields()})
				if _, ok := errors.AsType[*StreamError](err); !ok || !errors.Is(err, ErrDraining) {
					t.Fatalf("unsent stream Send = %v, want draining StreamError", err)
				}
				reset, err := p.endpoint.ReceiveStream(p.ctx, later)
				if err != nil || reset.Kind != Reset || !errors.Is(reset.Err, ErrDraining) {
					t.Fatalf("unsent GOAWAY reset = %+v, %v", reset, err)
				}
				if budget := p.endpoint.Budget(); budget.Granted != InitialStreamWindow {
					t.Fatalf("GOAWAY retained unsent reservation: %+v", budget)
				}
			}
			if err := p.framer.WritePing(false, [8]byte{1}); err != nil {
				t.Fatal(err)
			}
			frame := p.frame(t, func(f wireFrame) bool {
				return f.kind == http2.FrameRSTStream || f.kind == http2.FramePing || f.kind == http2.FrameGoAway
			})
			if frame.kind != http2.FramePing || !frame.flags.Has(http2.FlagPingAck) {
				t.Fatalf("draining connection wrote a reset or GOAWAY: %+v", frame)
			}
			fields := []hpack.HeaderField{{Name: ":status", Value: "204"}}
			p.headers(t, first.Stream, true, fields)
			response, err := p.endpoint.ReceiveStream(p.ctx, first)
			if err != nil || response.Kind != Headers || !response.EndStream {
				t.Fatalf("accepted first response = %+v, %v", response, err)
			}
			if test.started {
				p.headers(t, later.Stream, true, fields)
				response, err := p.endpoint.ReceiveStream(p.ctx, later)
				if err != nil || response.Kind != Headers || !response.EndStream {
					t.Fatalf("accepted later response = %+v, %v", response, err)
				}
			}
		})
	}
}
