// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnslayer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
	"github.com/zchee/mitmproxy-go/options"
)

// Bound real-socket stress runs to -count=20 -cpu=1,2,8: each TCP fixture
// consumes ephemeral ports until TIME_WAIT expires, even after prompt Close.
func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(layertest.Timeout):
		buf := make([]byte, 1<<20)
		t.Fatalf("operation did not complete:\n%s", buf[:runtime.Stack(buf, true)])
		var zero T
		return zero
	}
}

type observer struct {
	events   []string
	flows    []*flow.DNSFlow
	request  func(context.Context, *flow.DNSFlow) error
	response func(context.Context, *flow.DNSFlow) error
	failed   func(context.Context, *flow.DNSFlow) error
}

func (a *observer) DNSRequest(ctx context.Context, f *flow.DNSFlow) error {
	a.events = append(a.events, "dns_request")
	a.flows = append(a.flows, f)
	if a.request != nil {
		return a.request(ctx, f)
	}
	return nil
}

func (a *observer) DNSResponse(ctx context.Context, f *flow.DNSFlow) error {
	a.events = append(a.events, "dns_response")
	if a.response != nil {
		return a.response(ctx, f)
	}
	return nil
}

func (a *observer) DNSError(ctx context.Context, f *flow.DNSFlow) error {
	a.events = append(a.events, "dns_error")
	if a.failed != nil {
		return a.failed(ctx, f)
	}
	return nil
}

type session struct {
	client   net.Conn
	context  *layer.Context
	manager  *addon.Manager
	observed *observer
	logs     bytes.Buffer
	cancel   context.CancelFunc
	done     chan error
	finished chan struct{}
	udp      bool
}

func newSession(t *testing.T, udp bool, observed *observer) *session {
	t.Helper()
	if observed == nil {
		observed = &observer{}
	}
	manager := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	if err := manager.Add(t.Context(), observed); err != nil {
		t.Fatal(err)
	}
	s := &session{manager: manager, observed: observed, udp: udp}
	s.context = &layer.Context{
		Data:  &hookdata.Context{Client: connection.NewClient(connection.Address{}, connection.Address{}, 1), Server: connection.NewServer(nil)},
		Hooks: &proxy.HookRunner{Manager: manager}, Do: manager.Do,
		Logger: slog.New(slog.NewTextHandler(&s.logs, nil)), Record: proxy.Record,
	}
	if udp {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listener := packettransport.NewListener(t.Context(), socket)
		t.Cleanup(func() { _ = listener.Close() })
		peer, err := net.Dial("udp4", socket.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.Close() })
		if _, err := peer.Write([]byte("recorded handover")); err != nil {
			t.Fatal(err)
		}
		tuple, err := listener.Accept(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		var buf [64]byte
		if _, _, err := tuple.ReadFrom(buf[:]); err != nil {
			t.Fatal(err)
		}
		s.context.ClientPackets = proxy.RecordPackets(tuple)
		s.context.Data.Client.TransportProtocol = connection.UDP
		s.context.Data.Server.TransportProtocol = connection.UDP
		s.client = peer
	} else {
		peer, input := layertest.Pipe(t)
		s.client, s.context.Client = peer, proxy.Record(input)
	}
	if err := s.client.SetDeadline(time.Now().Add(layertest.Timeout)); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *session) start(t *testing.T) {
	t.Helper()
	selected, err := layer.Build(t.Context(), s.context, hookdata.LayerStack{{Kind: "dns"}})
	if err != nil {
		t.Fatal(err)
	}
	if selected.Kind() != "dns" {
		t.Fatalf("kind = %q", selected.Kind())
	}
	ctx, cancel := context.WithCancel(t.Context())
	s.cancel, s.done, s.finished = cancel, make(chan error, 1), make(chan struct{})
	t.Cleanup(func() { cancel(); await(t, s.finished) })
	go func() { s.done <- selected.Run(ctx, s.context); close(s.finished) }()
}

func (s *session) stop(t *testing.T) {
	t.Helper()
	s.cancel()
	err := await(t, s.done)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel = %v", err)
	}
	await(t, s.finished)
	for _, f := range s.observed.flows {
		if f.Live {
			t.Fatal("completed DNS flow is still live")
		}
	}
}

func query(id int) *dns.Message {
	return &dns.Message{ID: id, Query: true, RecursionDesired: true, Questions: []dns.Question{{Name: "example.test", Type: dns.TypeA, Class: dns.ClassIN}}}
}

func frame(t *testing.T, msg *dns.Message) []byte {
	t.Helper()
	wire, err := dns.Pack(msg)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(out, uint16(len(wire)))
	copy(out[2:], wire)
	return out
}

func (s *session) write(t *testing.T, msg *dns.Message) {
	t.Helper()
	wire := frame(t, msg)
	if s.udp {
		wire = wire[2:]
	}
	if _, err := s.client.Write(wire); err != nil {
		t.Fatal(err)
	}
}

func (s *session) read(t *testing.T) *dns.Message {
	t.Helper()
	var buf [65535]byte
	var size int
	if s.udp {
		n, err := s.client.Read(buf[:])
		if err != nil {
			t.Fatal(err)
		}
		size = n
	} else {
		var prefix [2]byte
		if _, err := io.ReadFull(s.client, prefix[:]); err != nil {
			t.Fatal(err)
		}
		size = int(binary.BigEndian.Uint16(prefix[:]))
		if _, err := io.ReadFull(s.client, buf[:size]); err != nil {
			t.Fatal(err)
		}
	}
	msg, err := dns.Unpack(buf[:size], nil)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// Upstream test_regular, test_regular_mode_no_hook and test_regular_hook_err
// cover both wire transports.
func TestResolution(t *testing.T) {
	tests := map[string]struct {
		udp    bool
		result string
	}{
		"TCP response": {result: "response"}, "UDP response": {udp: true, result: "response"},
		"TCP no hook": {}, "UDP no hook": {udp: true},
		"TCP hook error": {result: "error"}, "UDP hook error": {udp: true, result: "error"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := &observer{request: func(_ context.Context, f *flow.DNSFlow) error {
				switch tt.result {
				case "response":
					f.Response = f.Request.Succeed([]dns.ResourceRecord{dns.A("example.test", netip.MustParseAddr("192.0.2.1"), 60)})
				case "error":
					f.Error = flow.NewError("resolver failed")
				}
				return nil
			}}
			s := newSession(t, tt.udp, a)
			s.start(t)
			s.write(t, query(42))
			got := s.read(t)
			s.stop(t)
			wantEvents := []string{"dns_request", "dns_error"}
			want, err := query(42).Fail(dns.ResponseCodeSERVFAIL)
			if err != nil {
				t.Fatal(err)
			}
			if tt.result == "response" {
				wantEvents[1] = "dns_response"
				want = query(42).Succeed([]dns.ResourceRecord{dns.A("example.test", netip.MustParseAddr("192.0.2.1"), 60)})
			}
			want.Timestamp = nil
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff(wantEvents, a.events); diff != "" {
				t.Fatal(diff)
			}
			f := a.flows[0]
			if f.Request.Timestamp == nil {
				t.Fatal("request has no receive timestamp")
			}
			if tt.result == "" && f.Error.Msg != "No hook has set a response and there is no upstream server." {
				t.Fatalf("error = %v", f.Error)
			}
			if tt.result != "response" && f.Response != nil {
				t.Fatal("SERVFAIL became a response-hook flow")
			}
		})
	}
}

// Upstream test_invalid_and_dummy_end and test_invalid_tcp_message_length:
// malformed input logs and ends the transport without constructing a flow
// or firing dns_error.
func TestInvalid(t *testing.T) {
	tests := map[string]struct {
		udp        bool
		wire       []byte
		diagnostic string
	}{
		"UDP truncated header": {udp: true, wire: []byte{0, 1}},
		"TCP truncated header": {wire: []byte{0, 2, 0, 1}},
		"TCP zero length":      {wire: []byte{0, 0}, diagnostic: "Message length field cannot be zero"},
		"UDP missing question": {udp: true, wire: []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}},
		"TCP missing question": {wire: []byte{0, 12, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, tt.udp, nil)
			s.start(t)
			if _, err := s.client.Write(tt.wire); err != nil {
				t.Fatal(err)
			}
			if err := await(t, s.done); err == nil {
				t.Fatal("malformed DNS accepted")
			}
			await(t, s.finished)
			if len(s.observed.events) != 0 || len(s.observed.flows) != 0 {
				t.Fatal("malformed input created flow or hooks")
			}
			if !strings.Contains(s.logs.String(), "sent an invalid message:") || !strings.Contains(s.logs.String(), tt.diagnostic) {
				t.Fatalf("log = %q", s.logs.String())
			}
		})
	}
}

// Upstream test_reverse_with_query_resend reuses the same ID's flow;
// test_query_pipelining_same_event and test_query_pipelining_multiple_events
// preserve every framed message.
func TestTCPFramingAndResend(t *testing.T) {
	tests := map[string]struct{ fragmented, replay bool }{
		"pipelined": {}, "one-byte reads": {fragmented: true}, "recorded prefix": {replay: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, false, &observer{request: func(_ context.Context, f *flow.DNSFlow) error { f.Response = f.Request.Succeed(nil); return nil }})
			if tt.fragmented {
				s.context.Client = byteReader{s.context.Client}
			}
			first := frame(t, query(17))
			if tt.replay {
				if _, err := s.client.Write(first[:3]); err != nil {
					t.Fatal(err)
				}
				var buf [3]byte
				if _, err := io.ReadFull(s.context.Client, buf[:]); err != nil {
					t.Fatal(err)
				}
			}
			s.start(t)
			wire := append(first, frame(t, query(18))...)
			wire = append(wire, frame(t, query(17))...)
			if tt.replay {
				wire = wire[3:]
			}
			if _, err := s.client.Write(wire); err != nil {
				t.Fatal(err)
			}
			for _, id := range []int{17, 18, 17} {
				if got := s.read(t); got.ID != id {
					t.Fatalf("response ID = %d, want %d", got.ID, id)
				}
			}
			s.stop(t)
			if len(s.observed.flows) != 3 || s.observed.flows[0] != s.observed.flows[2] || s.observed.flows[0] == s.observed.flows[1] {
				t.Fatal("DNS ID flow matching failed")
			}
		})
	}
}

type byteReader struct{ layer.Recorder }

func (r byteReader) Read(p []byte) (int, error) { return r.Recorder.Read(p[:min(1, len(p))]) }

// Upstream test_reverse_premature_close closes without creating DNS flows.
func TestCancelAndClose(t *testing.T) {
	tests := map[string]struct{ udp, closeClient bool }{
		"TCP cancel": {}, "UDP cancel": {udp: true}, "TCP premature close": {closeClient: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, tt.udp, nil)
			s.start(t)
			if tt.closeClient {
				_ = s.client.Close()
				if err := await(t, s.done); err != nil {
					t.Fatal(err)
				}
				await(t, s.finished)
			} else {
				s.stop(t)
			}
		})
	}
}

func TestNoDirectHooks(t *testing.T) { layertest.NoDirectHooks(t) }
