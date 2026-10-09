// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

// Full-sequence map for py:test/mitmproxy/proxy/layers/http/test_http3.py at 3368a0a:
// test_ignore_push (386-388): TestHTTP3UpstreamIgnorePush.
// test_fail_without_header (390-403): TestHTTP3UpstreamFailWithoutHeader,
// internal-event sequence, adapter-level.
// test_invalid_header (406-434): TestRequiredRequestPseudoHeaders and TestRolePseudoValidation;
// covered with divergence documented in docs/compat.md internal/h3 (log-only wire reasons).
// test_simple (437-476): TestHTTP3ConsumerBorrowedExchange and TestHTTP3DriverTrailers.
// test_response_trailers (480-550): TestHTTP3DriverTrailers, both modes and hook mutation.
// test_request_trailers (554-611): TestHTTP3DriverTrailers, both modes and hook mutation.
// test_upstream_error (614-651): TestHTTP3UpstreamUpstreamError.
// test_http3_client_aborts (657-780): TestHTTP3ConsumerClientAborts, not duplicated here.
// test_rst_then_close (783-822): TestHTTP3UpstreamResetThenClose, acquisition-close subset.
// Post-FIN DATA is transport-owned, not injectable through quic-go v0.63.0 public API.
// test_cancel_then_server_disconnect (825-858): TestHTTP3UpstreamCancelThenServerDisconnect.
// test_cancel_during_response_hook (861-897): TestHTTP3UpstreamCancelDuringResponseHook.
// test_stream_concurrency (900-937): TestHTTP3UpstreamStreamConcurrency.
// test_stream_concurrent_get_connection (940-963): TestHTTP3UpstreamConcurrentAcquisition.
// test_kill_stream (966-1007): TestHTTP3UpstreamKillStream.
// test_receive_stop_sending (1011-1058): TestHTTP3UpstreamStopSending, observable subset.
// RESET/STOP orders while the request is open; STOP_SENDING after request FIN.
// Transport-owned: quic-go completes a fully read receive stream and drops later RESET_STREAM;
// upstream's completed-request reset row is a synthetic StreamReset injection.
// TestClient.test_no_data_on_closed_stream (1062-1097): TestHTTP3UpstreamNoDataAfterCancellation.
// TestClient.test_ignore_wrong_order (1099-1141): TestHTTP3UpstreamWrongOrder,
// internal-event sequence, adapter-level.
// test_early_server_data (1144-1171): TestHTTP3UpstreamEarlyServerData.
// Baseline: four full sequences covered, one covered with divergence, thirteen uncovered.
// Encoder-only and initialization-only subsets do not certify the remaining full sequences.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/quic-go/qpack"
	quic "github.com/quic-go/quic-go"

	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h3"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layers/httplayer/h3test"
)

type http3UpstreamSession struct {
	ctx            context.Context
	c              *layer.Context
	peer, origin   *h3test.Peer
	client, server *quic.Conn
	recorder       *addontest.Recorder
	terminal       chan *flow.HTTPFlow
	cancel         context.CancelFunc
	joined         chan struct{}
}

func newHTTP3UpstreamSession(t *testing.T, edit func(string, *flow.HTTPFlow)) *http3UpstreamSession {
	t.Helper()
	ctx := http3TestContext(t)
	fixture, master := newTestStream(t, &streamAddon{edit: edit})
	s := &http3UpstreamSession{ctx: ctx, c: fixture.c, recorder: &addontest.Recorder{}, terminal: make(chan *flow.HTTPFlow, 16)}
	if err := master.Do(ctx, func(ctx context.Context) error {
		fixture.c.Data.Server.Address = &connection.Address{Host: "example.com", Port: 443}
		return master.Addons.Add(ctx, s.recorder)
	}); err != nil {
		t.Fatal(err)
	}
	finished := make(map[*flow.HTTPFlow]bool)
	s.c.Do = func(ctx context.Context, fn func(context.Context) error) error {
		return master.Do(ctx, func(ctx context.Context) error {
			err := fn(ctx)
			for _, call := range s.recorder.Calls() {
				if f, ok := call.Arg.(*flow.HTTPFlow); ok && !f.Live && !finished[f] {
					finished[f] = true
					s.terminal <- f
				}
			}
			return err
		})
	}
	s.peer, s.client = h3test.Pair(t, ctx, false)
	s.origin, s.server = h3test.Pair(t, ctx, true)
	s.peer.Init(t, ctx)
	return s
}

func (s *http3UpstreamSession) start(t *testing.T, initOrigin bool) {
	t.Helper()
	if initOrigin {
		s.origin.Init(t, s.ctx)
	}
	ctx, cancel := context.WithCancel(s.ctx)
	s.cancel, s.joined = cancel, make(chan struct{})
	go func() {
		defer close(s.joined)
		consumer := &httpLayer{route: routeConfig{mode: modeTransparent, validateInboundHeaders: true}}
		_ = consumer.RunQUIC(ctx, s.c, s.client, s.server)
	}()
	t.Cleanup(func() { cancel(); <-s.joined })
}

func (s *http3UpstreamSession) request(t *testing.T, path string, end bool) *quic.Stream {
	t.Helper()
	stream, err := s.peer.Conn.OpenStreamSync(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	h3test.WriteHeaders(t, stream, []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: path}})
	if end {
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return stream
}

func (s *http3UpstreamSession) finish(t *testing.T, path string, hooks []string) *flow.HTTPFlow {
	t.Helper()
	for {
		select {
		case f := <-s.terminal:
			if f.Request.Path != path {
				t.Fatalf("terminal flow path = %q; want %q", f.Request.Path, path)
			}
			if err := s.c.Do(s.ctx, func(context.Context) error {
				var actual []string
				for _, call := range s.recorder.Calls() {
					if call.Arg == f && slices.Contains([]string{"requestheaders", "request", "responseheaders", "response", "error"}, call.Hook) {
						actual = append(actual, call.Hook)
					}
				}
				if diff := gocmp.Diff(hooks, actual); diff != "" {
					return fmt.Errorf("hook order (-want +got):\n%s", diff)
				}
				if f.Live || f.Intercepted() {
					return errors.New("terminal flow remains live or intercepted")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			return f
		case <-s.ctx.Done():
			t.Fatal("waiting for terminal flow:", s.ctx.Err())
		}
	}
}

func upstreamReceive[T any](t *testing.T, ctx context.Context, channel <-chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		var zero T
		return zero
	}
}

func upstreamResponse(t *testing.T, stream *quic.Stream, status, body string) {
	t.Helper()
	h3test.WriteHeaders(t, stream, []qpack.HeaderField{{Name: ":status", Value: status}})
	if body != "" {
		h3test.WriteFrame(t, stream, 0, []byte(body))
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTP3UpstreamIgnorePush(t *testing.T) {
	// Certification: py:test/mitmproxy/proxy/layers/http/test_http3.py:386-388, test_ignore_push.
	// This upstream sequence initializes the connection; it does not inject a push promise.
	s := newHTTP3UpstreamSession(t, nil)
	s.start(t, true)
	settings := upstreamReceive(t, s.ctx, s.peer.Control)
	if settings.Kind != 4 {
		t.Fatalf("first control frame = %d; want SETTINGS", settings.Kind)
	}
	stream := s.request(t, "/no-push", true)
	origin, err := s.origin.Conn.AcceptStream(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	h3test.ReadMessage(t, origin)
	upstreamResponse(t, origin, "204", "")
	h3test.ReadMessage(t, stream)
	s.finish(t, "/no-push", []string{"requestheaders", "request", "responseheaders", "response"})
	s.cancel()
	<-s.joined
	for {
		select {
		case frame := <-s.peer.Control:
			if frame.Kind == 13 {
				t.Fatal("proxy advertised MAX_PUSH_ID")
			}
		default:
			return
		}
	}
}

func TestHTTP3UpstreamUpstreamError(t *testing.T) {
	// Certification: py:test/mitmproxy/proxy/layers/http/test_http3.py:614-651, test_upstream_error.
	s := newHTTP3UpstreamSession(t, func(name string, f *flow.HTTPFlow) {
		if name == "request" {
			f.Request.Host = "unavailable.test"
		}
	})
	s.c.RecordPackets = proxy.RecordPackets
	s.c.OpenPackets = func(context.Context, *connection.Server) (layer.PacketTransport, *connection.Server, error) {
		return nil, nil, errors.New("oops server <> error")
	}
	s.start(t, true)
	stream := s.request(t, "/unavailable", true)
	fields, body, _ := h3test.ReadMessage(t, stream)
	if len(fields) == 0 || fields[0].Value != "502" || !bytes.Contains(body, []byte("502 Bad Gateway")) || !bytes.Contains(body, []byte("server &lt;&gt; error")) {
		t.Fatalf("error response: fields=%v body=%q", fields, body)
	}
	f := s.finish(t, "/unavailable", []string{"requestheaders", "request", "error"})
	if err := s.c.Do(s.ctx, func(context.Context) error {
		if f.Error == nil || !strings.Contains(f.Error.Msg, "oops server <> error") {
			return fmt.Errorf("upstream flow error = %v", f.Error)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTP3UpstreamStreamConcurrency(t *testing.T) {
	// Certification: py:test/mitmproxy/proxy/layers/http/test_http3.py:900-937, test_stream_concurrency.
	paused := make(chan *flow.HTTPFlow, 1)
	s := newHTTP3UpstreamSession(t, func(name string, f *flow.HTTPFlow) {
		if name == "request" && f.Request.Path == "/first" {
			f.Intercept()
			paused <- f
		}
	})
	s.start(t, true)
	first := s.request(t, "/first", true)
	f := upstreamReceive(t, s.ctx, paused)
	second := s.request(t, "/second", true)
	origin, err := s.origin.Conn.AcceptStream(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	fields, _, _ := h3test.ReadMessage(t, origin)
	if fields[2].Value != "/second" || origin.StreamID() != 0 {
		t.Fatalf("overtaking request = %v id=%d", fields, origin.StreamID())
	}
	upstreamResponse(t, origin, "204", "")
	h3test.ReadMessage(t, second)
	s.finish(t, "/second", []string{"requestheaders", "request", "responseheaders", "response"})
	if err := s.c.Do(s.ctx, func(context.Context) error { f.Resume(); return nil }); err != nil {
		t.Fatal(err)
	}
	origin, err = s.origin.Conn.AcceptStream(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	fields, _, _ = h3test.ReadMessage(t, origin)
	if fields[2].Value != "/first" || origin.StreamID() != 4 {
		t.Fatalf("resumed request = %v id=%d", fields, origin.StreamID())
	}
	upstreamResponse(t, origin, "204", "")
	h3test.ReadMessage(t, first)
	s.finish(t, "/first", []string{"requestheaders", "request", "responseheaders", "response"})
}

func TestHTTP3UpstreamKillStream(t *testing.T) {
	// Certification: py:test/mitmproxy/proxy/layers/http/test_http3.py:966-1007, test_kill_stream.
	s := newHTTP3UpstreamSession(t, func(name string, f *flow.HTTPFlow) {
		if name == "requestheaders" && f.Request.Path == "/killed" {
			f.Error = flow.NewError(flow.KilledMessage)
		}
	})
	s.start(t, true)
	killed := s.request(t, "/killed", true)
	var byteBuffer [1]byte
	_, err := killed.Read(byteBuffer[:])
	reset, ok := errors.AsType[*quic.StreamError](err)
	if !ok || !reset.Remote || reset.ErrorCode != quic.StreamErrorCode(h3.ErrCodeInternal) {
		t.Fatalf("killed stream reset = %v", err)
	}
	f := s.finish(t, "/killed", []string{"requestheaders", "error"})
	if err := s.c.Do(s.ctx, func(context.Context) error {
		if f.Error == nil || f.Error.Msg != flow.KilledMessage {
			return fmt.Errorf("killed flow error = %v", f.Error)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	free := s.request(t, "/survivor", true)
	origin, err := s.origin.Conn.AcceptStream(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	fields, _, _ := h3test.ReadMessage(t, origin)
	if fields[2].Value != "/survivor" {
		t.Fatalf("killed request reached origin: %v", fields)
	}
	upstreamResponse(t, origin, "204", "")
	h3test.ReadMessage(t, free)
	s.finish(t, "/survivor", []string{"requestheaders", "request", "responseheaders", "response"})
}

func TestHTTP3UpstreamEarlyServerData(t *testing.T) {
	// Certification: py:test/mitmproxy/proxy/layers/http/test_http3.py:1144-1171, test_early_server_data.
	paused := make(chan *flow.HTTPFlow, 1)
	s := newHTTP3UpstreamSession(t, func(name string, f *flow.HTTPFlow) {
		if name == "request" {
			f.Intercept()
			paused <- f
		}
	})
	s.start(t, false)
	stream := s.request(t, "/early-settings", true)
	f := upstreamReceive(t, s.ctx, paused)
	s.origin.Init(t, s.ctx)
	settings := upstreamReceive(t, s.ctx, s.origin.Control)
	if settings.Kind != 4 {
		t.Fatalf("proxy control frame = %d; want SETTINGS", settings.Kind)
	}
	if err := s.c.Do(s.ctx, func(context.Context) error {
		if !f.Intercepted() {
			return errors.New("early server settings released request hook")
		}
		f.Resume()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	origin, err := s.origin.Conn.AcceptStream(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	fields, _, _ := h3test.ReadMessage(t, origin)
	if fields[2].Value != "/early-settings" {
		t.Fatalf("request after early settings = %v", fields)
	}
	upstreamResponse(t, origin, "204", "")
	h3test.ReadMessage(t, stream)
	s.finish(t, "/early-settings", []string{"requestheaders", "request", "responseheaders", "response"})
}

func TestHTTP3UpstreamCancelDuringResponseHook(t *testing.T) {
	// Certification: py:test/mitmproxy/proxy/layers/http/test_http3.py:861-897, test_cancel_during_response_hook.
	paused := make(chan *flow.HTTPFlow, 1)
	s := newHTTP3UpstreamSession(t, func(name string, f *flow.HTTPFlow) {
		if name == "response" {
			f.Intercept()
			paused <- f
		}
	})
	s.start(t, true)
	stream := s.request(t, "/cancel-response-hook", true)
	origin, err := s.origin.Conn.AcceptStream(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	h3test.ReadMessage(t, origin)
	upstreamResponse(t, origin, "204", "")
	f := upstreamReceive(t, s.ctx, paused)
	stream.CancelRead(quic.StreamErrorCode(h3.ErrCodeRequestCancelled))
	stream.CancelWrite(quic.StreamErrorCode(h3.ErrCodeRequestCancelled))
	if err := s.c.Do(s.ctx, func(context.Context) error { f.Resume(); return nil }); err != nil {
		t.Fatal(err)
	}
	s.finish(t, "/cancel-response-hook", []string{"requestheaders", "request", "responseheaders", "response"})
	if err := s.c.Do(s.ctx, func(context.Context) error {
		if f.Error != nil {
			return fmt.Errorf("response hook cancellation generated an error: %v", f.Error)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTP3UpstreamCancelThenServerDisconnect(t *testing.T) {
	// Certification: py:test/mitmproxy/proxy/layers/http/test_http3.py:825-858, test_cancel_then_server_disconnect.
	paused := make(chan *flow.HTTPFlow, 1)
	s := newHTTP3UpstreamSession(t, func(name string, f *flow.HTTPFlow) {
		if name == "error" {
			f.Intercept()
			paused <- f
		}
	})
	s.start(t, true)
	stream := s.request(t, "/cancel-disconnect", true)
	origin, err := s.origin.Conn.AcceptStream(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	h3test.ReadMessage(t, origin)
	stream.CancelRead(quic.StreamErrorCode(h3.ErrCodeRequestCancelled))
	f := upstreamReceive(t, s.ctx, paused)
	if err := s.origin.Conn.CloseWithError(0x100, "server disconnects after cancellation"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.server.Context().Done():
	case <-s.ctx.Done():
		t.Fatal(s.ctx.Err())
	}
	if err := s.c.Do(s.ctx, func(context.Context) error { f.Resume(); return nil }); err != nil {
		t.Fatal(err)
	}
	s.finish(t, "/cancel-disconnect", []string{"requestheaders", "request", "error"})
	<-s.joined
	if err := s.c.Do(s.ctx, func(context.Context) error {
		if f.Error == nil || !strings.Contains(f.Error.Msg, "stream closed by client") {
			return fmt.Errorf("first cancellation diagnostic = %v", f.Error)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTP3UpstreamConcurrentAcquisition(t *testing.T) {
	// Certification: py:test/mitmproxy/proxy/layers/http/test_http3.py:940-963, test_stream_concurrent_get_connection.
	requests := make(chan struct{}, 2)
	var target *net.UDPAddr
	s := newHTTP3UpstreamSession(t, func(name string, f *flow.HTTPFlow) {
		if name == "request" {
			f.Request.Host, f.Request.Port = target.IP.String(), target.Port
			requests <- struct{}{}
		}
	})
	listener, _ := h3test.Listener(t)
	target = listener.Addr().(*net.UDPAddr)
	if err := s.c.Do(s.ctx, func(ctx context.Context) error {
		return s.c.Hooks.(*proxy.HookRunner).Manager.Add(ctx, &http3RoutingTLS{})
	}); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}, 2), make(chan struct{})
	var opens atomic.Int32
	s.c.RecordPackets = proxy.RecordPackets
	s.c.OpenPackets = func(ctx context.Context, server *connection.Server) (layer.PacketTransport, *connection.Server, error) {
		opens.Add(1)
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		t.Cleanup(func() { _ = socket.Close() })
		return &http3RoutingPackets{PacketConn: socket, ctx: ctx, peer: target}, server, nil
	}
	s.start(t, true)
	first := s.request(t, "/acquire-first", true)
	upstreamReceive(t, s.ctx, requests)
	upstreamReceive(t, s.ctx, started)
	second := s.request(t, "/acquire-second", true)
	upstreamReceive(t, s.ctx, requests)
	close(release)
	conn, err := listener.Accept(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	peer := h3test.NewPeer(t, s.ctx, conn)
	peer.Init(t, s.ctx)
	for range 2 {
		stream, err := conn.AcceptStream(s.ctx)
		if err != nil {
			t.Fatal(err)
		}
		h3test.ReadMessage(t, stream)
		upstreamResponse(t, stream, "204", "")
	}
	h3test.ReadMessage(t, first)
	h3test.ReadMessage(t, second)
	if opens.Load() != 1 {
		t.Fatalf("concurrent origin acquisition attempts = %d; want 1", opens.Load())
	}
	for range 2 {
		f := upstreamReceive(t, s.ctx, s.terminal)
		if err := s.c.Do(s.ctx, func(context.Context) error {
			if f.Live || f.Error != nil {
				return fmt.Errorf("concurrent acquisition flow: live=%v error=%v", f.Live, f.Error)
			}
			var hooks []string
			for _, call := range s.recorder.Calls() {
				if call.Arg == f {
					hooks = append(hooks, call.Hook)
				}
			}
			if diff := gocmp.Diff([]string{"requestheaders", "request", "responseheaders", "response"}, hooks); diff != "" {
				return errors.New(diff)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHTTP3UpstreamResetThenClose(t *testing.T) {
	// Certification: py:test/mitmproxy/proxy/layers/http/test_http3.py:783-822, test_rst_then_close.
	// Post-FIN DATA is transport-owned, not injectable through quic-go v0.63.0 public API.
	// This row pins close during origin acquisition, not literal post-FIN protocol-error parity.
	s := newHTTP3UpstreamSession(t, func(name string, f *flow.HTTPFlow) {
		if name == "request" {
			f.Request.Host = "blocked.test"
		}
	})
	started := make(chan struct{}, 1)
	s.c.RecordPackets = proxy.RecordPackets
	s.c.OpenPackets = func(ctx context.Context, _ *connection.Server) (layer.PacketTransport, *connection.Server, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, nil, errors.New("connection cancelled")
	}
	s.start(t, true)
	s.request(t, "/close-acquisition", true)
	upstreamReceive(t, s.ctx, started)
	if err := s.peer.Conn.CloseWithError(0x10c, "peer closed connection"); err != nil {
		t.Fatal(err)
	}
	f := s.finish(t, "/close-acquisition", []string{"requestheaders", "request", "error"})
	<-s.joined
	if err := s.c.Do(s.ctx, func(context.Context) error {
		if f.Error == nil {
			return errors.New("closed acquisition has no flow error")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTP3UpstreamStopSending(t *testing.T) {
	// Certification: py:test/mitmproxy/proxy/layers/http/test_http3.py:1011-1058, test_receive_stop_sending.
	// RESET/STOP orders are observed while the request is open; STOP_SENDING after request FIN.
	// Transport-owned: quic-go completes a fully read receive stream and drops later RESET_STREAM.
	// Upstream's completed-request reset row is a synthetic StreamReset injection.
	tests := map[string]struct {
		stopFirst bool
		complete  bool
	}{
		"success: reset then stop":        {},
		"success: stop then reset":        {stopFirst: true},
		"success: stop after request FIN": {stopFirst: true, complete: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			paused := make(chan *flow.HTTPFlow, 1)
			s := newHTTP3UpstreamSession(t, func(name string, f *flow.HTTPFlow) {
				if name == "requestheaders" {
					f.Request.Stream = true
				}
				if name == "error" {
					f.Intercept()
					paused <- f
				}
			})
			s.start(t, true)
			stream := s.request(t, "/stop-orders", test.complete)
			origin, err := s.origin.Conn.AcceptStream(s.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if test.complete {
				h3test.ReadMessage(t, origin)
			} else {
				h3test.ReadHeaders(t, origin)
			}
			if test.stopFirst {
				stream.CancelRead(quic.StreamErrorCode(h3.ErrCodeRequestCancelled))
			} else {
				stream.CancelWrite(quic.StreamErrorCode(h3.ErrCodeRequestCancelled))
			}
			f := upstreamReceive(t, s.ctx, paused)
			if test.stopFirst {
				stream.CancelWrite(quic.StreamErrorCode(h3.ErrCodeRequestCancelled))
			} else {
				stream.CancelRead(quic.StreamErrorCode(h3.ErrCodeRequestCancelled))
			}
			if err := s.c.Do(s.ctx, func(context.Context) error { f.Resume(); return nil }); err != nil {
				t.Fatal(err)
			}
			hooks := []string{"requestheaders", "error"}
			if test.complete {
				hooks = []string{"requestheaders", "request", "error"}
			}
			s.finish(t, "/stop-orders", hooks)
			var data [1]byte
			_, err = origin.Read(data[:])
			if !test.complete {
				reset, ok := errors.AsType[*quic.StreamError](err)
				if !ok || !reset.Remote || reset.ErrorCode != quic.StreamErrorCode(h3.ErrCodeRequestCancelled) {
					t.Fatalf("origin cancellation = %v", err)
				}
			}
			free := s.request(t, "/after-stop", true)
			origin, err = s.origin.Conn.AcceptStream(s.ctx)
			if err != nil {
				t.Fatal(err)
			}
			h3test.ReadMessage(t, origin)
			upstreamResponse(t, origin, "204", "")
			h3test.ReadMessage(t, free)
			s.finish(t, "/after-stop", []string{"requestheaders", "request", "responseheaders", "response"})
		})
	}
}

func newHTTP3UpstreamAdapter(t *testing.T) (*h3test.Peer, *h3.Endpoint, layer.StreamIdentity, context.Context) {
	t.Helper()
	ctx := http3TestContext(t)
	peer, conn := h3test.Pair(t, ctx, true)
	peer.Init(t, ctx)
	engine, err := h3.New(conn, h3.Config{Descriptor: layer.EndpointDescriptor{Identity: "origin", Protocol: "h3"}, Client: true, ValidateInboundHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	joined := make(chan struct{})
	go func() { defer close(joined); _ = engine.Run(runCtx) }()
	t.Cleanup(func() { cancel(); <-joined })
	id, err := engine.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return peer, engine, id, ctx
}

func TestHTTP3UpstreamFailWithoutHeader(t *testing.T) {
	// Certification, internal-event sequence, adapter-level:
	// py:test/mitmproxy/proxy/layers/http/test_http3.py:390-403, test_fail_without_header.
	peer, engine, id, ctx := newHTTP3UpstreamAdapter(t)
	endpoint := &http3Server{engine: engine, identity: id, failureDone: engine.StreamFailed(id), id: 0, normalize: true}
	if err := endpoint.Send(ctx, ResponseProtocolError{ID: 0, Message: "first message", Code: Kill}); err != nil {
		t.Fatal(err)
	}
	stream, err := peer.Conn.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	_, err = stream.Read(data[:])
	reset, ok := errors.AsType[*quic.StreamError](err)
	if !ok || !reset.Remote || reset.ErrorCode != quic.StreamErrorCode(h3.ErrCodeInternal) {
		t.Fatalf("unheaded stream kill = %v; want internal-error reset", err)
	}
	if endpoint.sentHeaders {
		t.Fatal("kill emitted response headers")
	}
}

func TestHTTP3UpstreamWrongOrder(t *testing.T) {
	// Certification, internal-event sequence, adapter-level:
	// py:test/mitmproxy/proxy/layers/http/test_http3.py:1099-1141, TestClient.test_ignore_wrong_order.
	// The private Go adapter reports an error to its caller instead of Python's log command.
	peer, engine, id, ctx := newHTTP3UpstreamAdapter(t)
	endpoint := &http3Client{engine: engine, identity: id, failureDone: engine.StreamFailed(id), id: 1, normalize: true}
	tests := map[string]struct{ event RequestEvent }{
		"error: trailers before headers": {event: RequestTrailers{ID: 1, Trailers: httpmsg.Headers{{Name: []byte("x-trailer"), Value: []byte("")}}}},
		"error: end before headers":      {event: RequestEndOfMessage{ID: 1}},
		"error: data before headers":     {event: RequestData{ID: 1, Data: []byte("123")}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := endpoint.Send(ctx, test.event); err == nil {
				t.Fatal("invalid ordering was accepted")
			}
		})
	}
	head := RequestHeaders{ID: 1, Request: &httpmsg.Request{HTTPVersion: "HTTP/3", Method: "GET", Scheme: "http", Host: "example.com", Port: 80, Path: "/ordered"}}
	if err := endpoint.Send(ctx, head); err != nil {
		t.Fatal(err)
	}
	stream, err := peer.Conn.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fields := h3test.ReadHeaders(t, stream)
	if fields[2].Value != "/ordered" {
		t.Fatalf("headers after ignored invalid events = %v", fields)
	}
	if err := endpoint.Send(ctx, head); err == nil {
		t.Fatal("duplicate initial headers accepted")
	}
	if err := endpoint.Send(ctx, RequestEndOfMessage{ID: 1}); err != nil {
		t.Fatal(err)
	}
	end, err := h3test.ReadFrame(stream)
	if err != nil || end.Kind != 0 || len(end.Payload) != 0 {
		t.Fatalf("terminal frame = %+v; error=%v", end, err)
	}
	var data [1]byte
	if _, err := stream.Read(data[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("invalid internal events wrote payload: %v", err)
	}
}

func TestHTTP3UpstreamNoDataAfterCancellation(t *testing.T) {
	// Certification: py:test/mitmproxy/proxy/layers/http/test_http3.py:1062-1097, TestClient.test_no_data_on_closed_stream.
	peer, engine, id, ctx := newHTTP3UpstreamAdapter(t)
	endpoint := &http3Client{engine: engine, identity: id, failureDone: engine.StreamFailed(id), id: 1, normalize: true}
	if err := endpoint.Send(ctx, RequestHeaders{ID: 1, Request: &httpmsg.Request{HTTPVersion: "HTTP/3", Method: "GET", Scheme: "http", Host: "example.com", Port: 80, Path: "/cancelled"}, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	stream, err := peer.Conn.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h3test.ReadMessage(t, stream)
	h3test.WriteHeaders(t, stream, []qpack.HeaderField{{Name: ":status", Value: "200"}})
	if event, err := endpoint.Receive(ctx); err != nil {
		t.Fatal(err)
	} else if _, ok := event.(ResponseHeaders); !ok {
		t.Fatalf("initial response = %T", event)
	}
	if err := endpoint.Send(ctx, RequestProtocolError{ID: 1, Message: "cancelled", Code: ClientDisconnected}); err != nil {
		t.Fatal(err)
	}
	// A peer may have already queued DATA before STOP_SENDING reaches it.
	payload := []byte{0, 3, 'f', 'o', 'o'}
	_, writeErr := stream.Write(payload)
	if writeErr != nil {
		if reset, ok := errors.AsType[*quic.StreamError](writeErr); !ok || !reset.Remote || reset.ErrorCode != quic.StreamErrorCode(h3.ErrCodeRequestCancelled) {
			t.Fatal(writeErr)
		}
	}
	if event, err := endpoint.Receive(ctx); err == nil {
		if _, ok := event.(ResponseData); ok {
			t.Fatal("cancelled origin emitted ResponseData")
		}
	} else if !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	responseHead := make(chan struct{}, 1)
	s := newHTTP3UpstreamSession(t, func(name string, f *flow.HTTPFlow) {
		if name == "responseheaders" {
			responseHead <- struct{}{}
		}
	})
	s.start(t, true)
	request := s.request(t, "/cancelled-flow", true)
	origin, err := s.origin.Conn.AcceptStream(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	h3test.ReadMessage(t, origin)
	h3test.WriteHeaders(t, origin, []qpack.HeaderField{{Name: ":status", Value: "200"}})
	upstreamReceive(t, s.ctx, responseHead)
	request.CancelRead(quic.StreamErrorCode(h3.ErrCodeRequestCancelled))
	f := s.finish(t, "/cancelled-flow", []string{"requestheaders", "request", "responseheaders", "error"})
	_, lateErr := origin.Write([]byte{0, 3, 'f', 'o', 'o'})
	if lateErr != nil {
		if reset, ok := errors.AsType[*quic.StreamError](lateErr); !ok || !reset.Remote {
			t.Fatal(lateErr)
		}
	}
	if err := s.c.Do(s.ctx, func(context.Context) error {
		if f.Response == nil || len(f.Response.RawContent) != 0 || f.Error == nil {
			return fmt.Errorf("late DATA changed cancelled flow: response=%v error=%v", f.Response, f.Error)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
