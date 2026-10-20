// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package updates

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestWebUpdateLifecycle(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"real_hook_delivery_before_five_seconds": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p := f.connect(t)
			item := testflow.TFlow()
			item.ID = "hook-owned"
			start := time.Now()
			if err := f.m.Addons.Trigger(t.Context(), addon.RequestHeadersHook{Flow: item}); err != nil {
				t.Fatal(err)
			}
			message := p.message(t)
			if message.Type != "flows/add" || time.Since(start) >= 5*time.Second {
				t.Fatal("hook delivery exceeded its real-socket bound")
			}
		}},
		"fragments_1024_with_interleaved_ping": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p := f.connect(t)
			body := []byte(`{"type":"flows/updateFilter","payload":{"name":"fragmented","expr":""}}`)
			if err := p.ws.WriteFrame(gows.OpcodeText, false, body, false); err != nil {
				t.Fatal(err)
			}
			for index := 1; index < fragmentLimit; index++ {
				if index == 512 {
					if err := p.ws.WriteFrame(gows.OpcodePing, true, []byte("interleaved"), false); err != nil {
						t.Fatal(err)
					}
					pong := p.frame(t)
					if pong.Header.Opcode != gows.OpcodePong || !bytes.Equal(pong.Payload, []byte("interleaved")) {
						t.Fatal("explicit Pong payload mismatch")
					}
				}
				if err := p.ws.WriteFrame(gows.OpcodeContinuation, index == fragmentLimit-1, nil, false); err != nil {
					t.Fatal(err)
				}
			}
			message := p.message(t)
			if message.Type != "flows/filterUpdate" {
				t.Fatal("fragmented command not assembled")
			}
			assertJSON(t, message.Payload, map[string]any{"name": "fragmented", "matching_flow_ids": nil})
		}},
		"fragment_1025_closes_1009": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p := f.connect(t)
			if err := p.ws.WriteFrame(gows.OpcodeText, false, nil, false); err != nil {
				t.Fatal(err)
			}
			for index := 1; index <= fragmentLimit; index++ {
				if err := p.ws.WriteFrame(gows.OpcodeContinuation, index == fragmentLimit, nil, false); err != nil {
					t.Fatal(err)
				}
			}
			assertProtocolClose(t, p, gows.CloseMessageTooBig)
		}},
		"ten_mib_message_accepted": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p := f.connect(t)
			body := []byte(`{"type":"flows/updateFilter","payload":{"name":"limit","expr":""}}`)
			body = append(body, bytes.Repeat([]byte(" "), messageLimit-len(body))...)
			if err := p.ws.WriteFrame(gows.OpcodeBinary, true, body, false); err != nil {
				t.Fatal(err)
			}
			message := p.message(t)
			assertJSON(t, message.Payload, map[string]any{"name": "limit", "matching_flow_ids": nil})
		}},
		"oversized_header_rejected_before_allocation": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p := f.connect(t)
			header := gows.AppendHeader(nil, gows.Header{Fin: true, Opcode: gows.OpcodeBinary, Masked: true, Length: messageLimit + 1})
			if _, err := p.conn.Write(header); err != nil {
				t.Fatal(err)
			}
			assertProtocolClose(t, p, gows.CloseMessageTooBig)
		}},
		"invalid_text_retains_1007": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p := f.connect(t)
			if err := p.ws.WriteFrame(gows.OpcodeText, true, []byte{0xff}, false); err != nil {
				t.Fatal(err)
			}
			assertProtocolClose(t, p, gows.CloseInvalidFramePayloadData)
		}},
		"unmasked_frame_retains_1002": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p := f.connect(t)
			if _, err := p.conn.Write(gows.AppendHeader(nil, gows.Header{Fin: true, Opcode: gows.OpcodeText})); err != nil {
				t.Fatal(err)
			}
			assertProtocolClose(t, p, gows.CloseProtocolError)
		}},
		"invalid_filter_retains_internal_reason": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p := f.connect(t)
			p.command(t, "invalid", "~not-a-filter")
			assertClose(t, p, gows.CloseInternalServerErr, internalReason)
		}},
		"empty_close_is_echoed_empty_and_joined": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p := f.connect(t)
			c := onlyClient(t, f)
			if err := p.ws.WriteFrame(gows.OpcodeClose, true, nil, false); err != nil {
				t.Fatal(err)
			}
			frame := p.frame(t)
			if frame.Header.Opcode != gows.OpcodeClose || len(frame.Payload) != 0 {
				t.Fatal("empty Close became a reserved wire code")
			}
			await(t, c.done)
			do(t, f, func(context.Context) error {
				if len(f.h.clients) != 0 {
					t.Fatal("closed client retained")
				}
				return nil
			})
		}},
		"shutdown_deadline_aborts_and_joins": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			_ = f.connect(t)
			c := onlyClient(t, f)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := f.h.Close(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("Close=%v", err)
			}
			await(t, c.done)
			if err := f.h.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, status := f.open(t, nil, nil); status != 503 {
				t.Fatalf("closed hub admitted HTTP upgrade: %d", status)
			}
		}},
		"admission_before_upgrade":          {run: testAdmission},
		"peer_close_while_data_is_pending":  {run: testPendingPeerClose},
		"shutdown_during_inbound_fragments": {run: testInboundAbort},
		"missing_dependencies_fail_fast": {run: func(t *testing.T) {
			if h, err := New(t.Context(), Config{}); h != nil || err == nil {
				t.Fatal("missing dependencies accepted")
			}
		}},
	}
	for name, tt := range tests {
		t.Run(name, tt.run)
	}
}

func testPendingPeerClose(t *testing.T) {
	f := newFixture(t, nil)
	p := f.connect(t)
	c := onlyClient(t, f)
	item := testflow.TFlow()
	item.ID = "closing"
	if err := f.m.Addons.Trigger(t.Context(), addon.RequestHeadersHook{Flow: item}); err != nil {
		t.Fatal(err)
	}
	body := gows.AppendCloseBody(nil, gows.CloseNormalClosure, nil)
	if err := p.ws.WriteFrame(gows.OpcodeClose, true, body, false); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for {
		frame := p.frame(t)
		if frame.Header.Opcode == gows.OpcodeClose {
			closed, err := gows.ParseClose(frame.Payload)
			if err != nil || closed.Code != gows.CloseNormalClosure {
				t.Fatal("peer Close was not answered")
			}
			break
		}
		seen++
		if seen > 1 || frame.Header.Opcode != gows.OpcodeText {
			t.Fatal("unexpected data/control during close exchange")
		}
	}
	await(t, c.done)
}

func testInboundAbort(t *testing.T) {
	f := newFixture(t, nil)
	peers := []*testPeer{f.connect(t), f.connect(t), f.connect(t), f.connect(t)}
	started, finished := make(chan struct{}, len(peers)), make(chan struct{}, len(peers))
	for _, peer := range peers {
		go func() {
			err := peer.ws.WriteFrame(gows.OpcodeText, false, bytes.Repeat([]byte("x"), 2048), false)
			started <- struct{}{}
			for range 128 {
				if err != nil {
					break
				}
				err = peer.ws.WriteFrame(gows.OpcodeContinuation, false, bytes.Repeat([]byte("y"), 2048), false)
			}
			finished <- struct{}{}
		}()
	}
	for range peers {
		await(t, started)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := f.h.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close=%v", err)
	}
	for range peers {
		await(t, finished)
	}
	do(t, f, func(context.Context) error {
		if len(f.h.clients) != 0 {
			t.Fatal("inbound readers remained registered after Abort")
		}
		return nil
	})
}

func onlyClient(t *testing.T, f *streamFixture) *client {
	t.Helper()
	var result *client
	do(t, f, func(context.Context) error {
		if len(f.h.clients) != 1 {
			t.Fatalf("registry size=%d,want1", len(f.h.clients))
		}
		for c := range f.h.clients {
			result = c
		}
		return nil
	})
	return result
}

func assertProtocolClose(t *testing.T, p *testPeer, code gows.CloseCode) {
	t.Helper()
	frame := p.frame(t)
	if frame.Header.Opcode != gows.OpcodeClose {
		t.Fatalf("protocol failure sent opcode%d", frame.Header.Opcode)
	}
	closed, err := gows.ParseClose(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Code != code {
		t.Fatalf("protocol Close=%d,want%d", closed.Code, code)
	}
	_ = p.ws.WriteFrame(gows.OpcodeClose, true, frame.Payload, false)
}
