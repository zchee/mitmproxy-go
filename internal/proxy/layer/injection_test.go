// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layer

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
)

func TestInjectionErrors(t *testing.T) {
	tests := map[string]struct {
		sentinel error
		reason   InjectionReason
		text     string
	}{
		"full":           {sentinel: ErrInjectionFull, reason: InjectionFull, text: "proxy: injection queue is full"},
		"size":           {sentinel: ErrInjectionSize, reason: InjectionSize, text: "proxy: injected message exceeds size limit"},
		"type":           {sentinel: ErrInjectionType, reason: InjectionType, text: "proxy: injection requires a compatible protocol message"},
		"identity":       {sentinel: ErrInjectionIdentity, reason: InjectionIdentity, text: "proxy: injection flow identity mismatch"},
		"direction":      {sentinel: ErrInjectionDirection, reason: InjectionDirectionMismatch, text: "proxy: injection direction mismatch"},
		"closed":         {sentinel: ErrInjectionClosed, reason: InjectionClosed, text: "proxy: injected flow is not live"},
		"invalid reason": {sentinel: &InjectionError{}, text: "proxy: invalid injection"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := &InjectionError{Reason: tt.reason}
			if err.Error() != tt.text || !errors.Is(err, tt.sentinel) {
				t.Fatalf("error = %q, want %q matching %v", err.Error(), tt.text, tt.sentinel)
			}
			if errors.Is(err, &InjectionError{Reason: 255}) || errors.Is(err, (*InjectionError)(nil)) {
				t.Fatal("different or nil reason matched")
			}
			if got := errors.Is(err, net.ErrClosed); got != (tt.reason == InjectionClosed) {
				t.Fatalf("net.ErrClosed match = %v", got)
			}
		})
	}
	if InjectionCapacity != 64 || MaxInjectionBytes != 128<<10 {
		t.Fatal("injection bounds changed")
	}
	if DirectionUnspecified != 0 || DirectionFromClient == DirectionFromServer {
		t.Fatal("direction identities overlap")
	}
}

func TestBuildUDPIgnore(t *testing.T) {
	Register(hookdata.LayerUDP, func(_ *Context, spec hookdata.LayerSpec, child Layer) (Layer, error) {
		if !spec.Ignore {
			t.Error("UDP ignore setting lost")
		}
		return &stackLayer{kind: spec.Kind, child: child}, nil
	})
	defer registry.Delete(hookdata.LayerUDP)
	c := &Context{Data: &hookdata.Context{}, Do: func(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }}
	if _, err := Build(t.Context(), c, hookdata.LayerStack{{Kind: hookdata.LayerUDP, Ignore: true}}); err != nil {
		t.Fatal(err)
	}
}
