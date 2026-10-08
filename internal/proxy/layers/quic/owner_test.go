// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"context"
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestQUICLayerContract(t *testing.T) {
	// py:mitmproxy/proxy/layers/quic/_raw_layers.py:57,148 publishes these markers.
	tests := map[string]struct {
		value layer.Layer
		kind  hookdata.LayerKind
	}{
		"raw connection": {value: NewRawQuicLayer(nil), kind: "quic"},
		"stream":         {value: &QuicStreamLayer{}, kind: "quicstream"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.kind, tt.value.Kind()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestQUICOwnerRejectsMissingPackets(t *testing.T) {
	tests := map[string]struct{ ctx context.Context }{
		"active caller": {ctx: t.Context()},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if err := NewRawQuicLayer(nil).Run(tt.ctx, &layer.Context{}); err == nil {
				t.Fatal("missing packet context accepted")
			}
		})
	}
}

func TestQUICOwnerCancelledBeforeSniff(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := NewRawQuicLayer(nil).Run(ctx, &layer.Context{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller = %v", err)
	}
}
