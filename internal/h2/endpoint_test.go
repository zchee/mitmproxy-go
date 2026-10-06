// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type wireFrame struct {
	kind      http2.FrameType
	stream    uint32
	flags     http2.Flags
	data      []byte
	increment uint32
	code      http2.ErrCode
	settings  []http2.Setting
}

type pipePeer struct {
	endpoint *Endpoint
	conn     net.Conn
	framer   *http2.Framer
	frames   chan wireFrame
	ctx      context.Context
	done     chan error
	readDone chan struct{}
}

func newPipePeer(t *testing.T, cfg Config) *pipePeer {
	t.Helper()
	conn, peer := net.Pipe()
	cfg.Descriptor.Identity = "endpoint"
	e, err := New(conn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	p := &pipePeer{endpoint: e, conn: peer, framer: http2.NewFramer(peer, nil), frames: make(chan wireFrame, 256), ctx: ctx, done: make(chan error, 1), readDone: make(chan struct{})}
	go func() {
		err := e.Run(ctx)
		_ = conn.Close()
		p.done <- err
	}()
	go func() {
		defer close(p.readDone)
		defer close(p.frames)
		if cfg.Client {
			preface := make([]byte, len(http2.ClientPreface))
			if _, err := io.ReadFull(peer, preface); err != nil {
				return
			}
			if string(preface) != http2.ClientPreface {
				return
			}
		}
		fr := http2.NewFramer(nil, peer)
		fr.AllowIllegalReads = true
		for {
			frame, err := fr.ReadFrame()
			if err != nil {
				return
			}
			wire := wireFrame{kind: frame.Header().Type, stream: frame.Header().StreamID, flags: frame.Header().Flags}
			switch f := frame.(type) {
			case *http2.DataFrame:
				wire.data = bytes.Clone(f.Data())
			case *http2.HeadersFrame:
				wire.data = bytes.Clone(f.HeaderBlockFragment())
			case *http2.ContinuationFrame:
				wire.data = bytes.Clone(f.HeaderBlockFragment())
			case *http2.WindowUpdateFrame:
				wire.increment = f.Increment
			case *http2.RSTStreamFrame:
				wire.code = f.ErrCode
			case *http2.GoAwayFrame:
				wire.code, wire.data = f.ErrCode, bytes.Clone(f.DebugData())
			case *http2.PingFrame:
				wire.data = bytes.Clone(f.Data[:])
			case *http2.SettingsFrame:
				if err := f.ForeachSetting(func(s http2.Setting) error { wire.settings = append(wire.settings, s); return nil }); err != nil {
					return
				}
			}
			select {
			case p.frames <- wire:
			case <-ctx.Done():
				return
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = peer.Close()
		_ = conn.Close()
		select {
		case <-p.done:
		case <-ctx.Done():
			select {
			case <-p.done:
			case <-time.After(30 * time.Second):
				buf := make([]byte, 1<<20)
				n := runtime.Stack(buf, true)
				t.Fatalf("Run cleanup hung:\n%s", buf[:n])
			}
		}
		<-p.readDone
	})
	if !cfg.Client {
		if _, err := io.WriteString(peer, http2.ClientPreface); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func (p *pipePeer) settings(t *testing.T, settings ...http2.Setting) {
	t.Helper()
	if err := p.framer.WriteSettings(settings...); err != nil {
		t.Fatal(err)
	}
	p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameSettings && f.flags.Has(http2.FlagSettingsAck) })
}

func (p *pipePeer) frame(t *testing.T, accept func(wireFrame) bool) wireFrame {
	t.Helper()
	for {
		select {
		case frame, ok := <-p.frames:
			if !ok {
				t.Fatal("peer reader ended before expected frame")
			}
			if accept(frame) {
				return frame
			}
		case <-p.ctx.Done():
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			t.Fatalf("waiting for frame:\n%s", buf[:n])
		}
	}
}

func (p *pipePeer) headers(t *testing.T, stream uint32, end bool, fields []hpack.HeaderField) {
	t.Helper()
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, field := range fields {
		if err := enc.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, EndStream: end, EndHeaders: true, BlockFragment: block.Bytes()}); err != nil {
		t.Fatal(err)
	}
}

func requestFields() []hpack.HeaderField {
	return []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: "example.com"}}
}

func TestEmptyDataUsesNoQueuedChunks(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = conn.Close(); _ = peer.Close() }()
	e, err := New(conn, Config{Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
	if err != nil {
		t.Fatal(err)
	}
	o := newOwner(e, t.Context())
	s := o.newStream(1)
	s.inHeaders = true
	for range 100 {
		var wire bytes.Buffer
		if err := http2.NewFramer(&wire, nil).WriteData(1, false, nil); err != nil {
			t.Fatal(err)
		}
		frame, err := http2.NewFramer(nil, &wire).ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if err := o.data(frame.(*http2.DataFrame)); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range s.queue {
		if cap(q.event.Data) != 0 {
			t.Fatalf("empty frame allocated %d queued bytes", cap(q.event.Data))
		}
	}
}

func TestEndpointHeaderOrderAndTrailers(t *testing.T) {
	p := newPipePeer(t, Config{ValidateInboundHeaders: true})
	p.settings(t)
	fields := append(requestFields(), hpack.HeaderField{Name: "x-order", Value: "first"}, hpack.HeaderField{Name: "x-order", Value: "second"})
	p.headers(t, 1, false, fields)
	head, err := p.endpoint.Receive(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(fields, head.Headers); diff != "" {
		t.Fatal(diff)
	}
	if head.Kind != Headers || head.Identity.Stream != 1 {
		t.Fatalf("head = %+v", head)
	}
	if err := p.framer.WriteDataPadded(1, false, []byte("Hello, World!"), []byte{0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameWindowUpdate && f.stream == 0 })
	data, err := p.endpoint.ReceiveStream(p.ctx, head.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if data.Kind != Data || string(data.Data) != "Hello, World!" || cap(data.Data) != ChunkSize || data.Receipt.OriginalBytes() != 17 {
		t.Fatalf("DATA = %+v, receipt %d, cap %d", data, data.Receipt.OriginalBytes(), cap(data.Data))
	}
	if !data.Receipt.Complete() || data.Receipt.Complete() {
		t.Fatal("receipt did not settle exactly once")
	}
	p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameWindowUpdate && f.stream == 1 && f.increment == 17 })
	trailers := []hpack.HeaderField{{Name: "req-trailer-a", Value: "a"}, {Name: "req-trailer-b", Value: "b"}}
	p.headers(t, 1, true, trailers)
	tail, err := p.endpoint.ReceiveStream(p.ctx, head.Identity)
	if err != nil || tail.Kind != Trailers || !tail.EndStream {
		t.Fatalf("trailers = %+v, %v", tail, err)
	}
	if diff := cmp.Diff(trailers, tail.Headers); diff != "" {
		t.Fatal(diff)
	}
}

func TestEndpointValidation(t *testing.T) {
	tests := map[string]struct {
		validate  bool
		wantError bool
	}{
		"error: uppercase with validation":         {validate: true, wantError: true},
		"success: uppercase without normalization": {},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newPipePeer(t, Config{ValidateInboundHeaders: test.validate})
			p.settings(t)
			fields := append(requestFields(), hpack.HeaderField{Name: "X-Foo", Value: "bar"})
			p.headers(t, 1, true, fields)
			event, err := p.endpoint.Receive(p.ctx)
			if test.wantError {
				if event.Err == nil && err == nil {
					t.Fatal("uppercase accepted")
				}
				wire := p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameGoAway })
				if wire.code != http2.ErrCodeProtocol || !bytes.Contains(wire.data, []byte("HTTP/2 protocol error: Received uppercase header name b'X-Foo'.")) {
					t.Fatalf("GOAWAY = %+v", wire)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(fields, event.Headers); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

func TestSendFlowControlAndCancellation(t *testing.T) {
	p := newPipePeer(t, Config{Client: true})
	p.settings(t, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1}, http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 2})
	id, err := p.endpoint.OpenStream(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: id, Headers: requestFields()}); err != nil {
		t.Fatal(err)
	}
	p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameHeaders })
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.endpoint.Send(ctx, Event{Kind: Data, Identity: id, Data: []byte("abc")}) }()
	first := p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameData })
	if string(first.data) != "a" {
		t.Fatalf("first DATA = %q", first.data)
	}
	select {
	case err := <-done:
		t.Fatalf("Send completed on queue acceptance: %v", err)
	default:
	}
	if err := p.framer.WriteWindowUpdate(id.Stream, 1); err != nil {
		t.Fatal(err)
	}
	second := p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameData })
	if string(second.data) != "b" {
		t.Fatalf("second DATA = %q", second.data)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Send = %v", err)
	}
	if err := p.endpoint.CancelStream(id, http2.ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameRSTStream })
	if got := p.endpoint.Budget(); got.Granted != 0 {
		t.Fatalf("cancel budget = %+v", got)
	}
	if err := p.endpoint.Send(p.ctx, Event{Kind: Data, Identity: id}); err == nil {
		t.Fatal("closed stream Send succeeded")
	} else if _, ok := errors.AsType[*StreamError](err); !ok {
		t.Fatalf("closed stream Send = %v", err)
	}
}

func TestInformationalAndReset(t *testing.T) {
	p := newPipePeer(t, Config{Client: true, ValidateInboundHeaders: true})
	p.settings(t)
	id, err := p.endpoint.OpenStream(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: id, Headers: requestFields(), EndStream: true}); err != nil {
		t.Fatal(err)
	}
	p.headers(t, id.Stream, false, []hpack.HeaderField{{Name: ":status", Value: "103"}})
	info, err := p.endpoint.ReceiveStream(p.ctx, id)
	if err != nil || info.Kind != Informational {
		t.Fatalf("informational = %+v %v", info, err)
	}
	p.headers(t, id.Stream, false, []hpack.HeaderField{{Name: ":status", Value: "200"}})
	head, err := p.endpoint.ReceiveStream(p.ctx, id)
	if err != nil || head.Kind != Headers {
		t.Fatalf("response = %+v %v", head, err)
	}
	if err := p.framer.WriteData(id.Stream, false, []byte("pending")); err != nil {
		t.Fatal(err)
	}
	data, err := p.endpoint.ReceiveStream(p.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.framer.WriteRSTStream(id.Stream, http2.ErrCodeHTTP11Required); err != nil {
		t.Fatal(err)
	}
	reset, err := p.endpoint.ReceiveStream(p.ctx, id)
	if err != nil || reset.Kind != Reset || reset.Code != http2.ErrCodeHTTP11Required {
		t.Fatalf("reset = %+v %v", reset, err)
	}
	if data.Receipt.Complete() {
		t.Fatal("RST did not invalidate outstanding receipt")
	}
	if got := p.endpoint.Budget(); got.Granted != 0 {
		t.Fatalf("RST budget = %+v", got)
	}
}

func TestOpenWaitsForSettingsAndGoAway(t *testing.T) {
	p := newPipePeer(t, Config{Client: true})
	started := make(chan struct{})
	opened := make(chan result, 1)
	go func() {
		close(started)
		id, err := p.endpoint.OpenStream(p.ctx)
		opened <- result{event: Event{Identity: id}, err: err}
	}()
	<-started
	select {
	case r := <-opened:
		t.Fatalf("Open before settings = %+v", r)
	default:
	}
	p.settings(t)
	r := <-opened
	if r.err != nil {
		t.Fatal(r.err)
	}
	if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: r.event.Identity, Headers: requestFields()}); err != nil {
		t.Fatal(err)
	}
	if err := p.framer.WriteGoAway(0, http2.ErrCodeNo, []byte("retire")); err != nil {
		t.Fatal(err)
	}
	goaway, err := p.endpoint.Receive(p.ctx)
	if err != nil || goaway.Kind != GoAway || goaway.LastStreamID != 0 {
		t.Fatalf("GOAWAY = %+v %v", goaway, err)
	}
	if _, err := p.endpoint.OpenStream(p.ctx); err == nil {
		t.Fatal("Open after GOAWAY succeeded")
	}
	if got := p.endpoint.Budget(); got.Granted != 0 {
		t.Fatalf("GOAWAY budget = %+v", got)
	}
}
