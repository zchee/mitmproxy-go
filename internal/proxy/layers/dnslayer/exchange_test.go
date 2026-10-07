// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnslayer

import (
	"context"
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

type openPool struct {
	layer.ServerPool
	open func(context.Context, *connection.Server, layer.OpenOptions) (layer.Conn, *connection.Server, error)
}

func (p openPool) Open(ctx context.Context, server *connection.Server, opts layer.OpenOptions) (layer.Conn, *connection.Server, error) {
	return p.open(ctx, server, opts)
}

// Upstream test_reverse, test_reverse_with_query_resend and
// test_tcp_message_over_multiple_events: origin replies retain their IDs,
// and an unanswered resend is forwarded using the existing flow.
func TestReverseTCP(t *testing.T) {
	tests := map[string]struct{ lazy, fragment bool }{
		"connected": {}, "lazy origin": {lazy: true}, "fragmented reply": {fragment: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, false, nil)
			peer, input := layertest.Pipe(t)
			s.context.Data.Server.Address = &connection.Address{Host: "example.test", Port: 53}
			s.context.Server = proxy.Record(input)
			if tt.fragment {
				s.context.Server = byteReader{s.context.Server}
			}
			opens := 0
			if tt.lazy {
				s.context.Server = nil
				s.context.Pool = openPool{open: func(_ context.Context, server *connection.Server, opts layer.OpenOptions) (layer.Conn, *connection.Server, error) {
					opens++
					if !opts.Reuse {
						t.Error("origin did not request connection reuse")
					}
					return input, server, nil
				}}
			}
			s.start(t)
			for _, id := range []int{1, 2, 1} {
				s.write(t, query(id))
				want := frame(t, query(id))
				got := make([]byte, len(want))
				if _, err := io.ReadFull(peer, got); err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(want, got); diff != "" {
					t.Fatal(diff)
				}
			}
			for _, id := range []int{2, 1} {
				want := query(id).Succeed([]dns.ResourceRecord{})
				if _, err := peer.Write(frame(t, want)); err != nil {
					t.Fatal(err)
				}
				want.Timestamp = nil
				if diff := gocmp.Diff(want, s.read(t)); diff != "" {
					t.Fatal(diff)
				}
			}
			s.stop(t)
			if tt.lazy && opens != 1 {
				t.Fatalf("origin opened %d times", opens)
			}
			if s.observed.flows[0] != s.observed.flows[2] {
				t.Fatal("resend created another flow")
			}
			if diff := gocmp.Diff([]string{"dns_request", "dns_request", "dns_request", "dns_response", "dns_response"}, s.observed.events); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// Upstream test_reverse_fail_connection sends SERVFAIL, not dns_response.
func TestOpenFailure(t *testing.T) {
	tests := map[string]struct{ udp bool }{"TCP": {}, "UDP": {udp: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, tt.udp, nil)
			s.context.Data.Server.Address = &connection.Address{Host: "example.test", Port: 53}
			refused := errors.New("connection refused")
			if tt.udp {
				s.context.RecordPackets = proxy.RecordPackets
				s.context.OpenPackets = func(context.Context, *connection.Server) (layer.PacketTransport, *connection.Server, error) {
					return nil, nil, refused
				}
			} else {
				s.context.Pool = openPool{open: func(context.Context, *connection.Server, layer.OpenOptions) (layer.Conn, *connection.Server, error) {
					return nil, nil, refused
				}}
			}
			s.start(t)
			s.write(t, query(3))
			if got := s.read(t); got.ResponseCode != dns.ResponseCodeSERVFAIL {
				t.Fatalf("response = %+v", got)
			}
			s.stop(t)
			if diff := gocmp.Diff([]string{"dns_request", "dns_error"}, s.observed.events); diff != "" {
				t.Fatal(diff)
			}
			if f := s.observed.flows[0]; f.Live || f.Error.Msg != refused.Error() {
				t.Fatalf("failed flow = %+v", f)
			}
		})
	}
}

func TestIntercept(t *testing.T) {
	tests := map[string]struct{ action string }{
		"resume modified response": {action: "resume"}, "kill intercepted request": {action: "kill"}, "cancel intercepted request": {action: "cancel"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			intercepted := make(chan *flow.DNSFlow, 1)
			s := newSession(t, false, &observer{request: func(_ context.Context, f *flow.DNSFlow) error { f.Intercept(); intercepted <- f; return nil }})
			s.start(t)
			s.write(t, query(4))
			f := await(t, intercepted)
			if tt.action == "cancel" {
				s.stop(t)
			} else {
				if err := s.manager.Do(t.Context(), func(context.Context) error {
					if tt.action == "kill" {
						return f.Kill()
					}
					f.Response = f.Request.Succeed(nil)
					f.Response.AuthoritativeAnswer = true
					f.Resume()
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if tt.action == "resume" {
					if got := s.read(t); !got.AuthoritativeAnswer {
						t.Fatal("resumed hook edit was not forwarded")
					}
					s.stop(t)
				} else {
					if err := await(t, s.done); err == nil || err.Error() != flow.KilledMessage {
						t.Fatalf("killed Run = %v", err)
					}
					await(t, s.finished)
				}
			}
			if f.Live || f.Intercepted() {
				t.Fatal("finished flow is live or intercepted")
			}
		})
	}
}
