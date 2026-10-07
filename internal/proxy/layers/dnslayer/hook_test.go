// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnslayer

import (
	"context"
	"testing"

	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestResponseHookRemoval(t *testing.T) {
	tests := map[string]struct{ udp bool }{"TCP": {}, "UDP": {udp: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			removed := make(chan struct{}, 1)
			s := newSession(t, tt.udp, &observer{
				request: func(_ context.Context, f *flow.DNSFlow) error { f.Response = f.Request.Succeed(nil); return nil },
				response: func(_ context.Context, f *flow.DNSFlow) error {
					if f.Response.ID == 1 {
						f.Response = nil
						removed <- struct{}{}
					} else {
						f.Response.AuthoritativeAnswer = true
					}
					return nil
				},
			})
			s.start(t)
			s.write(t, query(1))
			await(t, removed)
			s.write(t, query(2))
			if got := s.read(t); got.ID != 2 || !got.AuthoritativeAnswer {
				t.Fatalf("hook-edited response = %+v", got)
			}
			s.stop(t)
		})
	}
}

func TestErrorHookRequestMutation(t *testing.T) {
	tests := map[string]struct{ udp bool }{"TCP": {}, "UDP": {udp: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, tt.udp, &observer{failed: func(_ context.Context, f *flow.DNSFlow) error { f.Request.ID = 123; return nil }})
			s.start(t)
			s.write(t, query(1))
			if got := s.read(t); got.ID != 123 || got.ResponseCode != dns.ResponseCodeSERVFAIL {
				t.Fatalf("error-hook response = %+v", got)
			}
			s.stop(t)
		})
	}
}

func TestMissingContext(t *testing.T) {
	tests := map[string]struct{ context *layer.Context }{
		"nil": {}, "empty": {context: &layer.Context{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if err := New().Run(t.Context(), tt.context); err == nil {
				t.Fatal("invalid context accepted")
			}
		})
	}
}
