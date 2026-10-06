// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestReceiveChunksGateOriginalCredit(t *testing.T) {
	p := newPipePeer(t, Config{})
	p.settings(t)
	p.headers(t, 1, false, requestFields())
	head, err := p.endpoint.Receive(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.headers(t, 3, false, requestFields())
	other, err := p.endpoint.Receive(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{'x'}, ChunkSize)
	for range InitialStreamWindow / ChunkSize {
		if err := p.framer.WriteData(1, false, payload); err != nil {
			t.Fatal(err)
		}
		p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameWindowUpdate && f.stream == 0 })
		if got := p.endpoint.Budget(); got.Granted != 2*InitialStreamWindow {
			t.Fatalf("credit before consumption = %+v", got)
		}
	}
	first, err := p.endpoint.ReceiveStream(p.ctx, head.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Data) != ChunkSize || first.Receipt.OriginalBytes() != ChunkSize {
		t.Fatalf("first chunk = %+v", first)
	}
	pending := newRequest(p.ctx, receiveStream)
	pending.id = head.Identity
	p.endpoint.requests <- pending
	// A separate stream send is an owner-roundtrip after the blocked receive.
	if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: other.Identity, Headers: []hpack.HeaderField{{Name: ":status", Value: "200"}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-pending.result:
		t.Fatalf("second receipt delivered before first settled: %+v", r)
	default:
	}
	if !first.Receipt.Complete() {
		t.Fatal("receipt not settled")
	}
	second := <-pending.result
	if second.err != nil {
		t.Fatal(second.err)
	}
	if len(second.event.Data) != ChunkSize {
		t.Fatalf("second chunk size = %d", len(second.event.Data))
	}
	if !second.event.Receipt.Complete() {
		t.Fatal("second receipt not settled")
	}
	for range 2 {
		event, err := p.endpoint.ReceiveStream(p.ctx, head.Identity)
		if err != nil {
			t.Fatal(err)
		}
		if !event.Receipt.Complete() {
			t.Fatal("receipt not settled")
		}
	}
	p.frame(t, func(f wireFrame) bool {
		return f.kind == http2.FrameWindowUpdate && f.stream == 1 && f.increment >= InitialStreamWindow
	})
	if got := p.endpoint.Budget(); got.Granted != 3*InitialStreamWindow {
		t.Fatalf("growth at half-window = %+v", got)
	}
	if err := p.endpoint.CancelStream(head.Identity, http2.ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	if got := p.endpoint.Budget(); got.Granted != InitialStreamWindow {
		t.Fatalf("cancellation budget = %+v", got)
	}
}

func TestPeerLimitsAndDataReframing(t *testing.T) {
	p := newPipePeer(t, Config{Client: true})
	initial := p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameSettings && !f.flags.Has(http2.FlagSettingsAck) })
	want := []http2.Setting{{ID: http2.SettingMaxConcurrentStreams, Val: 100}, {ID: http2.SettingInitialWindowSize, Val: 1 << 20}, {ID: http2.SettingMaxFrameSize, Val: 1 << 17}, {ID: http2.SettingEnablePush, Val: 0}}
	if diff := cmp.Diff(want, initial.settings); diff != "" {
		t.Fatal(diff)
	}
	p.settings(t, http2.Setting{ID: http2.SettingInitialWindowSize, Val: InitialStreamWindow}, http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1}, http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384}, http2.Setting{ID: http2.SettingHeaderTableSize, Val: 0})
	id, err := p.endpoint.OpenStream(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	blocked := newRequest(p.ctx, openStream)
	p.endpoint.requests <- blocked
	if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: id, Headers: requestFields()}); err != nil {
		t.Fatal(err)
	}
	wireHead := p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameHeaders })
	if len(wireHead.data) == 0 || wireHead.data[0] != 0x20 {
		t.Fatalf("peer HPACK zero-table limit ignored: %x", wireHead.data)
	}
	select {
	case r := <-blocked.result:
		t.Fatalf("peer concurrency limit ignored: %+v", r)
	default:
	}
	if err := p.framer.WriteWindowUpdate(0, ChunkSize*2); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{'b'}, ChunkSize*2)
	done := make(chan error, 1)
	go func() {
		done <- p.endpoint.Send(p.ctx, Event{Kind: Data, Identity: id, Data: payload, EndStream: true})
	}()
	var received []byte
	for len(received) < len(payload) {
		wire := p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameData })
		if len(wire.data) > 16384 {
			t.Fatalf("peer frame limit exceeded: %d", len(wire.data))
		}
		received = append(received, wire.data...)
		if wire.flags.Has(http2.FlagDataEndStream) != (len(received) == len(payload)) {
			t.Fatal("END_STREAM not on final frame")
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("re-framing changed payload")
	}
	p.headers(t, id.Stream, true, []hpack.HeaderField{{Name: ":status", Value: "200"}})
	event, err := p.endpoint.ReceiveStream(p.ctx, id)
	if err != nil || !event.EndStream {
		t.Fatalf("terminal response = %+v %v", event, err)
	}
	opened := <-blocked.result
	if opened.err != nil || opened.event.Identity.Stream != 3 {
		t.Fatalf("concurrency release = %+v", opened)
	}
}

func TestProtocolRejections(t *testing.T) {
	tests := map[string]struct {
		write func(*pipePeer) error
		code  http2.ErrCode
	}{
		"error: oversized frame prefix": {write: func(p *pipePeer) error { _, err := p.conn.Write([]byte{2, 0, 1, 0, 0, 0, 0, 0, 1}); return err }, code: http2.ErrCodeFrameSize},
		"error: invalid SETTINGS stream window": {write: func(p *pipePeer) error {
			return p.framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0xffffffff})
		}, code: http2.ErrCodeFlowControl},
		"error: PUSH_PROMISE": {write: func(p *pipePeer) error {
			return p.framer.WritePushPromise(http2.PushPromiseParam{StreamID: 1, PromiseID: 2, EndHeaders: true, BlockFragment: []byte{0x82}})
		}, code: http2.ErrCodeProtocol},
		"error: DATA on idle stream":          {write: func(p *pipePeer) error { return p.framer.WriteData(1, false, []byte("early")) }, code: http2.ErrCodeProtocol},
		"error: CONTINUATION without HEADERS": {write: func(p *pipePeer) error { return p.framer.WriteContinuation(1, true, []byte{0x88}) }, code: http2.ErrCodeProtocol},
		"error: forbidden transfer encoding": {write: func(p *pipePeer) error {
			p.headers(t, 1, true, append(requestFields(), hpack.HeaderField{Name: "transfer-encoding", Value: "chunked"}))
			return nil
		}, code: http2.ErrCodeProtocol},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newPipePeer(t, Config{ValidateInboundHeaders: true})
			p.settings(t)
			if err := test.write(p); err != nil {
				t.Fatal(err)
			}
			wire := p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameGoAway })
			if wire.code != test.code {
				t.Fatalf("GOAWAY code = %v, want %v", wire.code, test.code)
			}
		})
	}
}

func TestWaitSendCreditAndShutdownCancellation(t *testing.T) {
	p := newPipePeer(t, Config{Client: true})
	p.settings(t, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0})
	id, err := p.endpoint.OpenStream(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	credit := newRequest(p.ctx, waitSendCredit)
	credit.id = id
	p.endpoint.requests <- credit
	if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: id, Headers: requestFields()}); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-credit.result:
		t.Fatalf("zero stream credit accepted: %+v", r)
	default:
	}
	if err := p.framer.WriteWindowUpdate(id.Stream, 1); err != nil {
		t.Fatal(err)
	}
	if r := <-credit.result; r.err != nil {
		t.Fatal(r.err)
	}
	ctx, cancel := context.WithCancel(p.ctx)
	if err := p.endpoint.Shutdown(ctx, http2.ErrCodeNo, []byte("retire")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.endpoint.OpenStream(p.ctx); err == nil {
		t.Fatal("Open after shutdown succeeded")
	}
	cancel()
	<-p.endpoint.Done()
	if got := p.endpoint.Budget(); got.Granted != 0 {
		t.Fatalf("shutdown budget = %+v", got)
	}
	if !errors.Is(p.endpoint.endError(), context.Canceled) {
		t.Fatalf("shutdown cancellation = %v", p.endpoint.endError())
	}
}

func TestConnectPseudoHeaders(t *testing.T) {
	tests := map[string]struct {
		fields  []hpack.HeaderField
		wantErr bool
	}{
		"success: classic CONNECT": {fields: []hpack.HeaderField{{Name: ":method", Value: "CONNECT"}, {Name: ":authority", Value: "example.com:443"}}},
		"error: CONNECT with path": {fields: []hpack.HeaderField{{Name: ":method", Value: "CONNECT"}, {Name: ":authority", Value: "example.com:443"}, {Name: ":path", Value: "/"}}, wantErr: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := checkPseudo(test.fields, false); (err != nil) != test.wantErr {
				t.Fatalf("pseudo headers error = %v", err)
			}
		})
	}
}

func TestEmptyEndDataAndClosedStream(t *testing.T) {
	p := newPipePeer(t, Config{})
	p.settings(t)
	p.headers(t, 1, false, requestFields())
	head, err := p.endpoint.Receive(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: head.Identity, Headers: []hpack.HeaderField{{Name: ":status", Value: "200"}}}); err != nil {
		t.Fatal(err)
	}
	if err := p.framer.WriteData(1, true, nil); err != nil {
		t.Fatal(err)
	}
	event, err := p.endpoint.ReceiveStream(p.ctx, head.Identity)
	if err != nil || !event.EndStream || len(event.Data) != 0 || event.Receipt.OriginalBytes() != 0 {
		t.Fatalf("empty terminal DATA = %+v, %v", event, err)
	}
	if !event.Receipt.Complete() {
		t.Fatal("empty receipt did not complete")
	}
	if err := p.endpoint.Send(p.ctx, Event{Kind: Data, Identity: head.Identity, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	terminal := p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameData })
	if !terminal.flags.Has(http2.FlagDataEndStream) || len(terminal.data) != 0 {
		t.Fatalf("empty outbound DATA = %+v", terminal)
	}
	if err := p.framer.WriteData(1, false, []byte("late")); err != nil {
		t.Fatal(err)
	}
	reset := p.frame(t, func(f wireFrame) bool {
		if f.kind == http2.FrameWindowUpdate && f.stream == 1 {
			t.Fatal("closed stream WINDOW_UPDATE emitted")
		}
		return f.kind == http2.FrameRSTStream
	})
	if reset.code != http2.ErrCodeStreamClosed {
		t.Fatalf("closed stream reset = %+v", reset)
	}
	p.frame(t, func(f wireFrame) bool {
		if f.kind == http2.FrameWindowUpdate && f.stream == 1 {
			t.Fatal("closed stream WINDOW_UPDATE emitted")
		}
		return f.kind == http2.FrameWindowUpdate && f.stream == 0
	})
	if got := p.endpoint.Budget(); got.Granted != 0 {
		t.Fatalf("closed budget = %+v", got)
	}
}

func TestSettingsControlQueueBound(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = conn.Close(); _ = peer.Close() }()
	e, err := New(conn, Config{Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
	if err != nil {
		t.Fatal(err)
	}
	o := newOwner(e, t.Context())
	settings := make([]http2.Setting, MaxConcurrentStreams*3)
	for i := range settings {
		settings[i] = http2.Setting{ID: http2.SettingHeaderTableSize, Val: 0}
	}
	var wire bytes.Buffer
	if err := http2.NewFramer(&wire, nil).WriteSettings(settings...); err != nil {
		t.Fatal(err)
	}
	frame, err := http2.NewFramer(nil, &wire).ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if err := o.settings(frame.(*http2.SettingsFrame)); err == nil {
		t.Fatal("unbounded SETTINGS control queue accepted")
	}
	if len(o.controls) > MaxConcurrentStreams*2 {
		t.Fatalf("control queue = %d", len(o.controls))
	}
}

func TestRepeatedCancellationKeepsOpening(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = conn.Close(); _ = peer.Close() }()
	e, err := New(conn, Config{Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
	if err != nil {
		t.Fatal(err)
	}
	o := newOwner(e, t.Context())
	for i := range MaxConcurrentStreams * 3 {
		s := o.newStream(uint32(i*2 + 1))
		if s == nil {
			t.Fatalf("stream %d refused after preceding cancellation", i)
		}
		o.cancel(s, http2.ErrCodeCancel, streamError(s.id, http2.ErrCodeCancel, "cancelled"), false)
		if got := e.Budget(); got.Granted != 0 {
			t.Fatalf("cancellation left reservation: %+v", got)
		}
	}
	if len(o.streams) > MaxConcurrentStreams*2 {
		t.Fatalf("unbounded cancelled state: %d", len(o.streams))
	}
}

func TestTerminalTrailers(t *testing.T) {
	tests := map[string]struct{ response bool }{"success: request trailers": {}, "success: response trailers": {response: true}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newPipePeer(t, Config{Client: test.response, ValidateInboundHeaders: true})
			p.settings(t)
			var id layer.StreamIdentity
			if test.response {
				var err error
				id, err = p.endpoint.OpenStream(p.ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: id, Headers: requestFields(), EndStream: true}); err != nil {
					t.Fatal(err)
				}
				p.headers(t, id.Stream, false, []hpack.HeaderField{{Name: ":status", Value: "200"}})
				if _, err := p.endpoint.ReceiveStream(p.ctx, id); err != nil {
					t.Fatal(err)
				}
			} else {
				p.headers(t, 1, false, requestFields())
				head, err := p.endpoint.Receive(p.ctx)
				if err != nil {
					t.Fatal(err)
				}
				id = head.Identity
			}
			if err := p.framer.WriteData(id.Stream, false, []byte("body")); err != nil {
				t.Fatal(err)
			}
			body, err := p.endpoint.ReceiveStream(p.ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			body.Receipt.Complete()
			fields := []hpack.HeaderField{{Name: "x-trailer", Value: "one"}, {Name: "x-trailer", Value: "two"}}
			p.headers(t, id.Stream, true, fields)
			tail, err := p.endpoint.ReceiveStream(p.ctx, id)
			if err != nil || tail.Kind != Trailers || !tail.EndStream {
				t.Fatalf("tail = %+v, %v", tail, err)
			}
			if diff := cmp.Diff(fields, tail.Headers); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestBodyLengthAndEarlyResponseRejections(t *testing.T) {
	tests := map[string]struct {
		response bool
		length   string
		body     string
	}{
		"error: request longer than content length":  {length: "1", body: "long"},
		"error: request shorter than content length": {length: "9", body: "short"},
		"error: server DATA before response headers": {response: true, body: "early"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newPipePeer(t, Config{Client: test.response, ValidateInboundHeaders: true})
			p.settings(t)
			stream := uint32(1)
			if test.response {
				id, err := p.endpoint.OpenStream(p.ctx)
				if err != nil {
					t.Fatal(err)
				}
				stream = id.Stream
				if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: id, Headers: requestFields(), EndStream: true}); err != nil {
					t.Fatal(err)
				}
			} else {
				p.headers(t, stream, false, append(requestFields(), hpack.HeaderField{Name: "content-length", Value: test.length}))
				if _, err := p.endpoint.Receive(p.ctx); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.framer.WriteData(stream, true, []byte(test.body)); err != nil {
				t.Fatal(err)
			}
			wantKind := http2.FrameRSTStream
			if test.response {
				wantKind = http2.FrameGoAway
			}
			wire := p.frame(t, func(f wireFrame) bool { return f.kind == wantKind })
			if wire.code != http2.ErrCodeProtocol {
				t.Fatalf("protocol code = %v", wire.code)
			}
		})
	}
}

func TestAltSvcIgnored(t *testing.T) {
	p := newPipePeer(t, Config{})
	p.settings(t)
	if err := p.framer.WriteRawFrame(http2.FrameType(0x0a), 0, 0, []byte("ignored")); err != nil {
		t.Fatal(err)
	}
	ping := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	if err := p.framer.WritePing(false, ping); err != nil {
		t.Fatal(err)
	}
	wire := p.frame(t, func(f wireFrame) bool {
		if f.kind == http2.FrameType(0x0a) {
			t.Fatal("Alt-Svc forwarded")
		}
		return f.kind == http2.FramePing && f.flags.Has(http2.FlagPingAck)
	})
	if !bytes.Equal(wire.data, ping[:]) {
		t.Fatalf("PING ACK = %x", wire.data)
	}
}

var _ layer.Clock = (*testClock)(nil)
