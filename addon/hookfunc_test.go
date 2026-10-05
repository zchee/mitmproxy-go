// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package addon

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
)

type mutationHook struct {
	onRequest func(context.Context, *flow.HTTPFlow) error
	onUpdate  func(context.Context, []flow.Flow) error
}

func (h *mutationHook) Request(ctx context.Context, f *flow.HTTPFlow) error {
	return h.onRequest(ctx, f)
}

func (h *mutationHook) Update(ctx context.Context, flows []flow.Flow) error {
	if h.onUpdate != nil {
		return h.onUpdate(ctx, flows)
	}
	return nil
}

func awaitMutation[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(30 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("hook operation did not complete:\n%s", buf[:n])
		var zero T
		return zero
	}
}

func TestHookFuncAtomicMutation(t *testing.T) {
	e := newEnv(t)
	f := flow.NewHTTPFlow(nil, nil, true)
	prepared := make(chan struct{})
	attempting := make(chan struct{})
	observed := make(chan string, 1)
	h := &mutationHook{onRequest: func(_ context.Context, f *flow.HTTPFlow) error {
		if f.Comment != "prepared" {
			t.Errorf("request saw %q, want prepared", f.Comment)
		}
		f.Comment = "handled"
		return nil
	}}
	if err := e.m.Add(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	go func() {
		<-prepared
		close(attempting)
		if err := e.m.Do(t.Context(), func(context.Context) error {
			observed <- f.Comment
			return nil
		}); err != nil {
			t.Error(err)
		}
	}()
	if err := e.m.HookFunc(t.Context(), func(ctx context.Context) error {
		f.Comment = "prepared"
		close(prepared)
		awaitMutation(t, attempting)
		_, err := Concurrent(ctx, func(context.Context) error {
			t.Error("prepare released the lock")
			return nil
		})
		if !errors.Is(err, ErrSyncContext) {
			t.Errorf("prepare Concurrent: %v", err)
		}
		return nil
	}, RequestHook{Flow: f}, nil); err != nil {
		t.Fatal(err)
	}
	if got := awaitMutation(t, observed); got != "handled" {
		t.Fatalf("outside mutation saw %q, want handled", got)
	}
}

func TestHookFuncFinishesAfterConcurrentAndUpdate(t *testing.T) {
	e := newEnv(t)
	f := flow.NewHTTPFlow(nil, nil, true)
	var order []string
	h := &mutationHook{
		onRequest: func(ctx context.Context, _ *flow.HTTPFlow) error {
			order = append(order, "hook")
			_, err := Concurrent(ctx, func(ctx context.Context) error {
				return e.m.Do(ctx, func(context.Context) error {
					order = append(order, "concurrent")
					return nil
				})
			})
			return err
		},
		onUpdate: func(ctx context.Context, _ []flow.Flow) error {
			_, err := Concurrent(ctx, func(context.Context) error { return nil })
			order = append(order, "update")
			return err
		},
	}
	if err := e.m.Add(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	if err := e.m.HookFunc(t.Context(), func(context.Context) error {
		order = append(order, "prepare")
		return nil
	}, RequestHook{Flow: f}, func(ctx context.Context) {
		_, err := Concurrent(ctx, func(context.Context) error {
			t.Error("finish released the lock")
			return nil
		})
		if !errors.Is(err, ErrSyncContext) {
			t.Errorf("finish Concurrent: %v", err)
		}
		if err := e.m.Do(ctx, func(context.Context) error {
			order = append(order, "finish")
			return nil
		}); err != nil {
			t.Error(err)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]string{"prepare", "hook", "concurrent", "update", "finish"}, order); diff != "" {
		t.Fatalf("dispatch order (-want +got):\n%s", diff)
	}
}

func TestHookFuncPrepareError(t *testing.T) {
	e := newEnv(t)
	want := errors.New("invalid mutation")
	h := &mutationHook{onRequest: func(context.Context, *flow.HTTPFlow) error {
		t.Error("hook ran after prepare error")
		return nil
	}}
	if err := e.m.Add(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	err := e.m.HookFunc(t.Context(), func(context.Context) error { return want }, RequestHook{}, func(context.Context) {
		t.Error("finish ran after prepare error")
	})
	if !errors.Is(err, want) {
		t.Fatalf("HookFunc: %v, want %v", err, want)
	}
}

func TestHookFlow(t *testing.T) {
	f := flow.NewHTTPFlow(nil, nil, true)
	tests := map[string]struct {
		hook Hook
		want flow.Flow
	}{
		"flow":     {RequestHook{Flow: f}, f},
		"pointer":  {&ResponseHook{Flow: f}, f},
		"no flow":  {RunningHook{}, nil},
		"nil flow": {RequestHook{}, nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := HookFlow(tt.hook); got != tt.want {
				t.Fatalf("HookFlow(%T) = %v, want %v", tt.hook, got, tt.want)
			}
		})
	}
}
