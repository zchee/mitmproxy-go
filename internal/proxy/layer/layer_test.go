// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layer

import (
	"context"
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/options"
)

type stackLayer struct {
	kind  hookdata.LayerKind
	child Layer
}

func (l *stackLayer) Kind() hookdata.LayerKind { return l.kind }
func (l *stackLayer) Run(ctx context.Context, c *Context) error {
	if l.child != nil {
		return l.child.Run(ctx, c)
	}
	return nil
}

func TestBuildStackUnderHold(t *testing.T) {
	m := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
	t.Cleanup(m.Close)
	const outer, inner hookdata.LayerKind = "test-outer", "test-inner"
	var constructed []hookdata.LayerKind
	inHold := false
	for _, kind := range []hookdata.LayerKind{outer, inner} {
		Register(kind, func(_ *Context, spec hookdata.LayerSpec, child Layer) (Layer, error) {
			if !inHold {
				t.Error("constructor ran outside dispatch hold")
			}
			constructed = append(constructed, spec.Kind)
			return &stackLayer{spec.Kind, child}, nil
		})
		defer registry.Delete(kind)
	}
	c := &Context{Data: &hookdata.Context{}, Do: func(ctx context.Context, fn func(context.Context) error) error {
		return m.Do(ctx, func(ctx context.Context) error { inHold = true; defer func() { inHold = false }(); return fn(ctx) })
	}}
	var got Layer
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		var err error
		got, err = Build(ctx, c, hookdata.LayerStack{{Kind: outer}, {Kind: inner}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]hookdata.LayerKind{inner, outer}, constructed); diff != "" {
		t.Fatal(diff)
	}
	if got != c.Data.Layers[0] || got.(*stackLayer).child != c.Data.Layers[1] {
		t.Fatal("stack order or child does not match published layers")
	}
}

func TestBuildRefusesInvalidStack(t *testing.T) {
	const failing, wrong, nilLayer hookdata.LayerKind = "test-failing", "test-wrong", "test-nil"
	Register(failing, func(*Context, hookdata.LayerSpec, Layer) (Layer, error) { return nil, errors.New("cannot construct") })
	Register(wrong, func(*Context, hookdata.LayerSpec, Layer) (Layer, error) { return &stackLayer{kind: failing}, nil })
	Register(nilLayer, func(*Context, hookdata.LayerSpec, Layer) (Layer, error) { return nil, nil })
	defer registry.Delete(failing)
	defer registry.Delete(wrong)
	defer registry.Delete(nilLayer)
	tests := map[string]struct{ stack hookdata.LayerStack }{
		"empty":              {},
		"unknown":            {hookdata.LayerStack{{Kind: "not-registered"}}},
		"failed constructor": {hookdata.LayerStack{{Kind: failing}}},
		"wrong kind":         {hookdata.LayerStack{{Kind: wrong}}},
		"nil layer":          {hookdata.LayerStack{{Kind: nilLayer}}},
		"mode in child":      {hookdata.LayerStack{{Kind: hookdata.LayerRegular}}},
		"non HTTP mode":      {hookdata.LayerStack{{Kind: failing, HTTPMode: hookdata.HTTPModeRegular}}},
		"ignore not TCP":     {hookdata.LayerStack{{Kind: failing, Ignore: true}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			existing := &stackLayer{kind: "existing"}
			c := &Context{Data: &hookdata.Context{Layers: []any{existing}}, Do: func(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }}
			if _, err := Build(t.Context(), c, tt.stack); err == nil {
				t.Fatal("invalid stack accepted")
			}
			if len(c.Data.Layers) != 1 || c.Data.Layers[0] != existing {
				t.Fatal("failed Build modified published stack")
			}
		})
	}
}

func TestNextPassesCurrentContext(t *testing.T) {
	want := &stackLayer{kind: "selected"}
	c := &Context{}
	c.NextLayer = func(ctx context.Context, got *Context) (Layer, error) {
		if got != c || ctx != t.Context() {
			t.Error("Next did not forward the current context")
		}
		return want, nil
	}
	got, err := Next(t.Context(), c)
	if err != nil || got != want {
		t.Fatalf("Next: %v, %v", got, err)
	}
}

func TestSnapshotKilled(t *testing.T) {
	var s *Snapshot
	if s.Killed() {
		t.Fatal("nil snapshot is killed")
	}
}
