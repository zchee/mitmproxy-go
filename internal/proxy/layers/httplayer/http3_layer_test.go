// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"testing"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestHTTP3LayerRegistration(t *testing.T) {
	tests := map[string]struct {
		stack   hookdata.LayerStack
		refused bool
	}{
		"registered connection consumer": {stack: hookdata.LayerStack{{Kind: hookdata.LayerHTTP3}}},
		"byte stream child refused":      {stack: hookdata.LayerStack{{Kind: hookdata.LayerHTTP3}, {Kind: hookdata.LayerHTTP, HTTPMode: hookdata.HTTPModeTransparent}}, refused: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture, _ := newTestStream(t, &streamAddon{})
			built, err := layer.Build(t.Context(), fixture.c, test.stack)
			if test.refused {
				if err == nil {
					t.Fatal("HTTP/3 connection accepted a byte-stream child")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := built.(*http3Layer); !ok || built.Kind() != hookdata.LayerHTTP3 {
				t.Fatalf("HTTP/3 constructor = %T, kind %q", built, built.Kind())
			}
			if err := fixture.c.Do(t.Context(), func(_ context.Context) error {
				if len(fixture.c.Data.Layers) != 1 || fixture.c.Data.Layers[0] != built {
					return errors.New("registered stack did not publish HTTP/3 kind")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
