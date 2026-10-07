// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestFramerErrorLocalStreamState(t *testing.T) {
	tests := map[string]struct {
		client       bool
		id           uint32
		wantReset    bool
		wantProtocol bool
	}{
		"success: absent closed local stream": {client: true, id: 1},
		"error: absent idle local stream":     {client: true, id: 5, wantProtocol: true},
		"success: client peer stream reset":   {client: true, id: 2, wantReset: true},
		"success: server stream reset":        {id: 1, wantReset: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			conn, peer := net.Pipe()
			t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
			e, err := New(conn, Config{Client: test.client, Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			o := newOwner(e, ctx)
			o.peerSettings, o.controls, o.lastLocal, o.nextLocal = true, nil, 3, 5
			// Retain controls behind an active write so the terminal queue is observable.
			o.active = &writeFrame{kind: writePing}
			reads := make(chan readFrame)
			stopped := make(chan struct{})
			go func() {
				err := o.run(reads, nil, nil)
				o.closeAll(err)
				close(e.done)
				close(stopped)
			}()
			t.Cleanup(func() { cancel(); <-stopped })
			select {
			case reads <- readFrame{err: http2.StreamError{StreamID: test.id, Code: http2.ErrCodeProtocol}}:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			// An owner request after the unbuffered read handoff is a processing barrier.
			_ = e.WaitSendCredit(ctx, layer.StreamIdentity{Endpoint: "endpoint"})
			cancel()
			<-stopped
			failure, failed := errors.AsType[*ProtocolError](o.fatal)
			if failed != test.wantProtocol || failed && failure.Code != http2.ErrCodeProtocol {
				t.Fatalf("framer failure = %v, want connection PROTOCOL_ERROR=%v", o.fatal, test.wantProtocol)
			}
			wantControls := 0
			if test.wantReset {
				wantControls = 1
			}
			if len(o.controls) != wantControls {
				t.Fatalf("framer queued %d controls, want %d", len(o.controls), wantControls)
			}
			if test.wantReset {
				reset := o.controls[0]
				if reset.kind != writeReset || reset.stream != test.id || reset.code != http2.ErrCodeProtocol {
					t.Fatalf("framer reset = %+v", reset)
				}
			}
		})
	}
}
