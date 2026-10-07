// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestCancelStreamWireState(t *testing.T) {
	tests := map[string]struct {
		headers string
	}{
		"success: idle local stream":                      {headers: "idle"},
		"success: initial HEADERS write in flight":        {headers: "active"},
		"success: written HEADERS with cancelled context": {headers: "cancelled"},
		"success: completed HEADERS write":                {headers: "complete"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			conn, peer := net.Pipe()
			t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
			endpoint, err := New(conn, Config{Client: true, Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			o := newOwner(endpoint, ctx)
			// Drive the writer handoff directly to order cancellation and write completion.
			o.peerSettings, o.controls = true, nil
			writes := make(chan *writeFrame)
			written := make(chan writeResult, 1)
			stopped := make(chan struct{})
			endpoint.started.Store(true)
			go func() {
				err := o.run(nil, writes, written)
				o.closeAll(err)
				close(endpoint.done)
				close(stopped)
			}()
			t.Cleanup(func() { cancel(); <-stopped })
			id, err := endpoint.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			failed, done := endpoint.StreamFailed(id), endpoint.StreamDone(id)
			sendCtx, cancelSend := context.WithCancel(ctx)
			defer cancelSend()
			sent := make(chan error, 1)
			if test.headers != "idle" {
				go func() { sent <- endpoint.Send(sendCtx, Event{Kind: Headers, Identity: id, Headers: requestFields()}) }()
				frame := awaitCancelWrite(t, ctx, writes)
				if frame.kind != writeHeaders || frame.stream != id.Stream {
					t.Fatalf("initial write = %+v", frame)
				}
				switch test.headers {
				case "active":
					if err := endpoint.CancelStream(id, http2.ErrCodeCancel); err != nil {
						t.Fatal(err)
					}
				case "cancelled":
					cancelSend()
				}
				written <- writeResult{frame: frame}
				err := <-sent
				if test.headers == "complete" {
					if err != nil {
						t.Fatal(err)
					}
				} else if test.headers == "cancelled" {
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancelled Send = %v", err)
					}
				} else if failure, ok := errors.AsType[*StreamError](err); !ok || failure.Code != http2.ErrCodeCancel {
					t.Fatalf("in-flight cancelled Send = %v", err)
				}
			}
			for range 2 {
				if err := endpoint.CancelStream(id, http2.ErrCodeCancel); err != nil {
					t.Fatal(err)
				}
			}
			for _, signal := range []<-chan struct{}{failed, done} {
				select {
				case <-signal:
				default:
					t.Fatal("cancelled stream did not publish termination")
				}
			}
			reset, err := endpoint.ReceiveStream(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if reset.Kind != Reset || reset.Identity != id || reset.Code != http2.ErrCodeCancel {
				t.Fatalf("local cancellation = %+v", reset)
			}
			if test.headers == "cancelled" {
				if !errors.Is(reset.Err, context.Canceled) {
					t.Fatalf("local context cancellation = %v", reset.Err)
				}
			} else if failure, ok := errors.AsType[*StreamError](reset.Err); !ok || failure.Code != http2.ErrCodeCancel {
				t.Fatalf("local cancellation error = %v", reset.Err)
			}
			if budget := endpoint.Budget(); budget.Granted != 0 {
				t.Fatalf("cancelled reservation retained: %+v", budget)
			}
			next, err := endpoint.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(id.Stream+2, next.Stream); diff != "" {
				t.Fatalf("next local stream identity (-want +got):\n%s", diff)
			}
			go func() { sent <- endpoint.Send(ctx, Event{Kind: Headers, Identity: next, Headers: requestFields()}) }()
			if test.headers != "idle" {
				frame := awaitCancelWrite(t, ctx, writes)
				if frame.kind != writeReset || frame.stream != id.Stream || frame.code != http2.ErrCodeCancel {
					t.Fatalf("cancellation write = %+v", frame)
				}
				written <- writeResult{frame: frame}
			}
			// The next HEADERS is a positive barrier: no reset may precede an idle
			// cancellation, and no duplicate reset may follow an active cancellation.
			frame := awaitCancelWrite(t, ctx, writes)
			if frame.kind != writeHeaders || frame.stream != next.Stream {
				t.Fatalf("next stream write = %+v, want HEADERS stream %d", frame, next.Stream)
			}
			written <- writeResult{frame: frame}
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			cancel()
			<-stopped
			if _, retained := o.streams[id.Stream]; retained {
				t.Fatal("cancelled stream state retained after consumption")
			}
		})
	}
}

func TestCancelledStreamLateResponse(t *testing.T) {
	tests := map[string]struct {
		peerReset, unsent bool
	}{
		"success: response in flight after local reset":              {},
		"success: response in flight after peer reset":               {peerReset: true},
		"success: unsent cancellation closed by later local HEADERS": {unsent: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newPipePeer(t, Config{Client: true, ValidateInboundHeaders: true})
			p.settings(t)
			id, err := p.endpoint.OpenStream(p.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !test.unsent {
				if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: id, Headers: requestFields(), EndStream: true}); err != nil {
					t.Fatal(err)
				}
				p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameHeaders })
			}
			if test.peerReset {
				if err := p.framer.WriteRSTStream(id.Stream, http2.ErrCodeCancel); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := p.endpoint.CancelStream(id, http2.ErrCodeCancel); err != nil {
					t.Fatal(err)
				}
				if !test.unsent {
					p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameRSTStream })
				}
			}
			reset, err := p.endpoint.ReceiveStream(p.ctx, id)
			if err != nil || reset.Kind != Reset {
				t.Fatalf("local reset = %+v, %v", reset, err)
			}
			// Opening the sibling lets the owner settle the consumed reset and evict its state.
			sibling, err := p.endpoint.OpenStream(p.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: sibling, Headers: requestFields(), EndStream: true}); err != nil {
				t.Fatal(err)
			}
			head := p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameHeaders || f.kind == http2.FrameRSTStream })
			if head.kind != http2.FrameHeaders || head.stream != sibling.Stream {
				t.Fatalf("sibling request = %+v, want HEADERS stream %d without idle reset", head, sibling.Stream)
			}
			fields := []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "x-in-flight", Value: "shared dynamic table entry"}}
			var block bytes.Buffer
			encoder := hpack.NewEncoder(&block)
			for _, field := range fields {
				if err := encoder.WriteField(field); err != nil {
					t.Fatal(err)
				}
			}
			late := bytes.Clone(block.Bytes())
			block.Reset()
			for _, field := range fields {
				if err := encoder.WriteField(field); err != nil {
					t.Fatal(err)
				}
			}
			dependent := bytes.Clone(block.Bytes())
			if len(dependent) >= len(late) {
				t.Fatal("sibling block does not reuse the late response's dynamic table entry")
			}
			written := make(chan error, 1)
			go func() {
				if err := p.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: id.Stream, BlockFragment: late[:1]}); err != nil {
					written <- err
					return
				}
				if err := p.framer.WriteContinuation(id.Stream, true, late[1:]); err != nil {
					written <- err
					return
				}
				if err := p.framer.WriteData(id.Stream, true, []byte("late")); err != nil {
					written <- err
					return
				}
				if err := p.framer.WritePriority(id.Stream, http2.PriorityParam{}); err != nil {
					written <- err
					return
				}
				if err := p.framer.WriteWindowUpdate(id.Stream, 1); err != nil {
					written <- err
					return
				}
				if err := p.framer.WriteRSTStream(id.Stream, http2.ErrCodeCancel); err != nil {
					written <- err
					return
				}
				written <- p.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: sibling.Stream, EndStream: true, EndHeaders: true, BlockFragment: dependent})
			}()
			credit := p.frame(t, func(f wireFrame) bool {
				return f.kind == http2.FrameGoAway || f.kind == http2.FrameRSTStream || f.kind == http2.FrameWindowUpdate && f.stream == 0
			})
			if credit.kind != http2.FrameWindowUpdate || credit.increment != 4 {
				t.Fatalf("late response connection credit = %+v, want connection WINDOW_UPDATE increment 4", credit)
			}
			response, err := p.endpoint.ReceiveStream(p.ctx, sibling)
			if err != nil || response.Kind != Headers || !response.EndStream {
				t.Fatalf("sibling response = %+v, %v", response, err)
			}
			if diff := gocmp.Diff(fields, response.Headers); diff != "" {
				t.Fatalf("dependent sibling headers (-want +got):\n%s", diff)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if _, err := p.endpoint.ReceiveStream(p.ctx, id); err == nil || err.Error() != "h2: unknown or foreign stream" {
				t.Fatalf("closed stream state recreated: %v", err)
			}
		})
	}
}

func TestIdleLocalStreamFrames(t *testing.T) {
	tests := map[string]struct {
		allocated, cancelled bool
	}{
		"error: future stream":               {},
		"error: allocated idle stream":       {allocated: true},
		"error: evicted unsent cancellation": {allocated: true, cancelled: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			frames := map[string]func(*http2.Framer) error{
				"HEADERS": func(f *http2.Framer) error {
					return f.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, EndHeaders: true, BlockFragment: []byte{0x88}})
				},
				"DATA":          func(f *http2.Framer) error { return f.WriteData(3, true, []byte("idle")) },
				"WINDOW_UPDATE": func(f *http2.Framer) error { return f.WriteWindowUpdate(3, 1) },
				"RST_STREAM":    func(f *http2.Framer) error { return f.WriteRSTStream(3, http2.ErrCodeCancel) },
			}
			for kind, write := range frames {
				t.Run(kind, func(t *testing.T) {
					conn, peer := net.Pipe()
					t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
					e, err := New(conn, Config{Client: true, Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
					if err != nil {
						t.Fatal(err)
					}
					o := newOwner(e, t.Context())
					defer o.finishHead()
					o.peerSettings, o.controls, o.lastLocal, o.nextLocal = true, nil, 1, 3
					if test.allocated {
						s := o.newStream(3)
						o.nextLocal = 5
						if test.cancelled {
							o.cancel(s, http2.ErrCodeCancel, errors.New("cancelled before sending"), true)
							s.queue = nil
							o.settle()
						}
					}
					before := e.Budget()
					var wire bytes.Buffer
					if err := write(http2.NewFramer(&wire, nil)); err != nil {
						t.Fatal(err)
					}
					frame, err := http2.NewFramer(nil, &wire).ReadFrame()
					if err != nil {
						t.Fatal(err)
					}
					failure, ok := errors.AsType[*ProtocolError](o.frame(frame))
					if !ok || failure.Code != http2.ErrCodeProtocol {
						t.Fatalf("frame on wire-idle stream = %v, want connection PROTOCOL_ERROR", failure)
					}
					if diff := gocmp.Diff(before, e.Budget()); diff != "" {
						t.Fatalf("idle frame changed reservation (-want +got):\n%s", diff)
					}
					if len(o.credits) != 0 || len(o.controls) != 0 {
						t.Fatalf("idle frame generated controls or credits: %+v %+v", o.controls, o.credits)
					}
				})
			}
		})
	}
}

func TestPresentIdleLocalStreamFrames(t *testing.T) {
	tests := map[string]struct {
		write func(*http2.Framer) error
	}{
		"error: HEADERS on unsent lower stream": {write: func(f *http2.Framer) error {
			return f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: []byte{0x88}})
		}},
		"error: DATA on unsent lower stream": {write: func(f *http2.Framer) error {
			return f.WriteData(1, true, []byte("idle"))
		}},
		"error: WINDOW_UPDATE on unsent lower stream": {write: func(f *http2.Framer) error {
			return f.WriteWindowUpdate(1, 1)
		}},
		"error: RST_STREAM on unsent lower stream": {write: func(f *http2.Framer) error {
			return f.WriteRSTStream(1, http2.ErrCodeCancel)
		}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			conn, peer := net.Pipe()
			t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
			e, err := New(conn, Config{Client: true, Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
			if err != nil {
				t.Fatal(err)
			}
			o := newOwner(e, t.Context())
			defer o.finishHead()
			o.peerSettings, o.controls = true, nil
			idle, started := o.newStream(1), o.newStream(3)
			// Exercise retained idle state below the dispatched high-water mark,
			// independently of the initial-HEADERS ordering scheduler.
			started.wireStarted, o.lastLocal, o.nextLocal = true, 3, 5
			before := e.Budget()
			var wire bytes.Buffer
			if err := test.write(http2.NewFramer(&wire, nil)); err != nil {
				t.Fatal(err)
			}
			frame, err := http2.NewFramer(nil, &wire).ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			failure, ok := errors.AsType[*ProtocolError](o.frame(frame))
			if !ok || failure.Code != http2.ErrCodeProtocol {
				t.Fatalf("frame on present wire-idle stream = %v, want connection PROTOCOL_ERROR", failure)
			}
			if diff := gocmp.Diff(before, e.Budget()); diff != "" {
				t.Fatalf("idle frame changed reservation (-want +got):\n%s", diff)
			}
			if idle.inHeaders || idle.remoteEnd || idle.received != 0 || len(o.credits) != 0 || len(o.controls) != 0 {
				t.Fatalf("idle frame mutated stream or flow control: stream=%+v credits=%v controls=%v", idle, o.credits, o.controls)
			}
			o.fail(failure)
			goaway := o.nextWrite()
			if goaway == nil || goaway.kind != writeGoAway || goaway.code != http2.ErrCodeProtocol {
				t.Fatalf("connection failure write = %+v, want GOAWAY(PROTOCOL_ERROR)", goaway)
			}
			if budget := e.Budget(); budget.Granted != 0 {
				t.Fatalf("connection failure retained reservations: %+v", budget)
			}
			for _, s := range []*streamState{idle, started} {
				select {
				case <-s.done:
				default:
					t.Fatalf("stream %d remained open after connection failure", s.id.Stream)
				}
			}
		})
	}
}

func TestCancelledPresentStreamLateFrames(t *testing.T) {
	tests := map[string]struct {
		headFirst bool
	}{
		"success: late HEADERS then DATA": {headFirst: true},
		"success: late DATA then HEADERS": {},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newPipePeer(t, Config{Client: true})
			p.settings(t)
			id, err := p.endpoint.OpenStream(p.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: id, Headers: requestFields()}); err != nil {
				t.Fatal(err)
			}
			p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameHeaders })
			if err := p.endpoint.CancelStream(id, http2.ErrCodeCancel); err != nil {
				t.Fatal(err)
			}
			reset := p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameRSTStream })
			if reset.stream != id.Stream || reset.code != http2.ErrCodeCancel {
				t.Fatalf("cancellation reset = %+v", reset)
			}
			// Leave the terminal event unconsumed to retain the failed stream state.
			written := make(chan error, 1)
			go func() {
				head := func() error {
					return p.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: id.Stream, EndHeaders: true, BlockFragment: []byte{0x88}})
				}
				data := func() error { return p.framer.WriteData(id.Stream, true, []byte("late")) }
				first, second := data, head
				if test.headFirst {
					first, second = head, data
				}
				if err := first(); err != nil {
					written <- err
					return
				}
				if err := second(); err != nil {
					written <- err
					return
				}
				written <- p.framer.WritePing(false, [8]byte{1})
			}()
			var credit uint32
			var sibling layer.StreamIdentity
			for {
				frame := p.frame(t, func(f wireFrame) bool { return true })
				if frame.kind == http2.FrameRSTStream || frame.kind == http2.FrameGoAway {
					t.Fatalf("late frame generated a second reset or GOAWAY: %+v", frame)
				}
				if frame.kind == http2.FrameWindowUpdate {
					if frame.stream != 0 {
						t.Fatalf("closed stream received credit: %+v", frame)
					}
					credit += frame.increment
				}
				if frame.kind == http2.FramePing && frame.flags.Has(http2.FlagPingAck) {
					sibling, err = p.endpoint.OpenStream(p.ctx)
					if err != nil {
						t.Fatal(err)
					}
					if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: sibling, Headers: requestFields(), EndStream: true}); err != nil {
						t.Fatal(err)
					}
				}
				// The sibling HEADERS follows both peer-frame processing and pending credit.
				if frame.kind == http2.FrameHeaders && frame.stream == sibling.Stream {
					break
				}
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if credit != 4 {
				t.Fatalf("late DATA connection credit = %d, want exactly 4", credit)
			}
			terminal, err := p.endpoint.ReceiveStream(p.ctx, id)
			if err != nil || terminal.Kind != Reset || terminal.Code != http2.ErrCodeCancel {
				t.Fatalf("retained terminal event = %+v, %v", terminal, err)
			}
		})
	}
}

func awaitCancelWrite(t *testing.T, ctx context.Context, writes <-chan *writeFrame) *writeFrame {
	t.Helper()
	select {
	case frame := <-writes:
		return frame
	case <-ctx.Done():
		stack := make([]byte, 1<<20)
		t.Fatalf("owner writer handoff hung:\n%s", stack[:runtime.Stack(stack, true)])
		return nil
	}
}
