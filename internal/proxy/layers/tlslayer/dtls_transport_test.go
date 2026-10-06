// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"testing"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestDTLSRejectsStreamTransportBeforeHooks(t *testing.T) {
	tests := map[string]struct {
		kind hookdata.LayerKind
	}{
		"error: client DTLS cannot use a byte stream": {kind: hookdata.LayerClientDTLS},
		"error: server DTLS cannot use a byte stream": {kind: hookdata.LayerServerDTLS},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			observer := &tlsObserver{}
			s := newServerSession(t, observer)
			stack, err := layer.Build(t.Context(), s.c, hookdata.LayerStack{{Kind: tt.kind}})
			if err != nil {
				t.Fatalf("DTLS constructor not registered: %v", err)
			}
			if err := stack.Run(t.Context(), s.c); err == nil {
				t.Fatal("DTLS accepted missing packet transport")
			}
			if len(observer.events) != 0 {
				t.Fatalf("DTLS fired hooks on a byte stream: %v", observer.events)
			}
		})
	}
}
