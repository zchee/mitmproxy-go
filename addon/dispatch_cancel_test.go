// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package addon

import (
	"context"
	"errors"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
)

type namedMutationHook struct {
	*mutationHook
	name     string
	onAddons func()
	children []any
}

func (h *namedMutationHook) Name() string { return h.name }

func (h *namedMutationHook) Addons() []any {
	if h.onAddons != nil {
		h.onAddons()
	}
	return h.children
}

type admissionContext struct {
	context.Context //nolint:containedctx // Observes entry to a real context's cancellation select.
	waiting         chan struct{}
	once            sync.Once
}

func (c *admissionContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestDispatchCancelledAdmission(t *testing.T) {
	tests := map[string]struct {
		occupied bool
	}{
		"error: cancelled before admission":                      {},
		"error: cancelled while another callback holds dispatch": {occupied: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d := &dispatcher{}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			release := make(chan struct{})
			ownerDone := make(chan error, 1)
			if tt.occupied {
				entered := make(chan struct{})
				go func() {
					ownerDone <- d.do(t.Context(), func(context.Context) error {
						close(entered)
						<-release
						return nil
					})
				}()
				awaitMutation(t, entered)
			}
			if !tt.occupied {
				cancel()
			}
			observed := &admissionContext{Context: ctx, waiting: make(chan struct{})}
			result := make(chan error, 1)
			go func() {
				result <- d.do(observed, func(context.Context) error {
					t.Error("cancelled caller entered dispatch")
					return nil
				})
			}()
			if tt.occupied {
				awaitMutation(t, observed.waiting)
				cancel()
			}
			if err := awaitMutation(t, result); !errors.Is(err, context.Canceled) {
				t.Errorf("admission = %v, want context.Canceled", err)
			}
			if tt.occupied {
				close(release)
				if err := awaitMutation(t, ownerDone); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestConcurrentCancelledReacquisition(t *testing.T) {
	tests := map[string]struct {
		panics bool
	}{
		"error: body returns after cancellation": {},
		"error: body panics after cancellation":  {panics: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d, starts, ends := countingDispatcher()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var result error
			recovered := capturePanic(func() {
				result = d.do(ctx, func(ctx context.Context) error {
					next, err := Concurrent(ctx, func(context.Context) error {
						cancel()
						if tt.panics {
							panic("cancelled body")
						}
						return errors.New("body error")
					})
					if frameFrom(next) != nil {
						t.Error("cancelled reacquisition returned a dispatch frame")
					}
					if !errors.Is(err, context.Canceled) {
						t.Errorf("Concurrent = %v, want context.Canceled", err)
					}
					return nil // Even a swallowed cancellation must not revive the dispatch.
				})
			})
			if tt.panics {
				if recovered != "cancelled body" {
					t.Errorf("panic = %v, want cancelled body", recovered)
				}
			} else if recovered != nil || !errors.Is(result, context.Canceled) {
				t.Errorf("dispatch = %v, panic = %v, want context.Canceled without panic", result, recovered)
			}
			if *starts != 1 || *ends != 1 {
				t.Errorf("holds = %d acquisitions, %d releases, want one each", *starts, *ends)
			}
			if err := d.do(t.Context(), func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConcurrentDerivedCancellation(t *testing.T) {
	tests := map[string]struct {
		update bool
		panics bool
	}{
		"error: request child context cancelled": {},
		"error: update child context cancelled":  {update: true},
		"error: request child context panics":    {panics: true},
		"error: update child context panics":     {update: true, panics: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			var order []string
			yield := func(ctx context.Context) error {
				child, cancel := context.WithCancel(ctx)
				defer cancel()
				_, _ = Concurrent(child, func(context.Context) error {
					cancel()
					if tt.panics {
						panic("child cancelled")
					}
					return nil
				})
				return nil
			}
			h := &mutationHook{
				onRequest: func(ctx context.Context, _ *flow.HTTPFlow) error {
					order = append(order, "request")
					if !tt.update {
						return yield(ctx)
					}
					return nil
				},
				onUpdate: func(ctx context.Context, _ []flow.Flow) error {
					order = append(order, "update")
					return yield(ctx)
				},
			}
			if err := e.m.Add(t.Context(), h); err != nil {
				t.Fatal(err)
			}
			err := e.m.HookFunc(t.Context(), nil, RequestHook{Flow: flow.NewHTTPFlow(nil, nil, true)}, func(context.Context) {
				order = append(order, "finish")
			})
			if !errors.Is(err, context.Canceled) {
				t.Errorf("HookFunc = %v, want child context.Canceled", err)
			}
			if t.Context().Err() != nil {
				t.Fatal("child cancellation propagated to the outer context")
			}
			want := []string{"request"}
			if tt.update {
				want = append(want, "update")
			}
			if diff := gocmp.Diff(want, order); diff != "" {
				t.Errorf("hook order (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCancelledUpdateSkipsFinish(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var order []string
	h := &mutationHook{
		onRequest: func(context.Context, *flow.HTTPFlow) error {
			order = append(order, "request")
			return nil
		},
		onUpdate: func(ctx context.Context, _ []flow.Flow) error {
			order = append(order, "update")
			_, _ = Concurrent(ctx, func(context.Context) error {
				cancel()
				return nil
			})
			return ErrAddonHalt
		},
	}
	if err := e.m.Add(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	err := e.m.HookFunc(ctx, nil, RequestHook{Flow: flow.NewHTTPFlow(nil, nil, true)}, func(context.Context) {
		order = append(order, "finish")
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("HookFunc = %v, want context.Canceled", err)
	}
	if diff := gocmp.Diff([]string{"request", "update"}, order); diff != "" {
		t.Errorf("hook order (-want +got):\n%s", diff)
	}
}

func TestCancelledHookDoesNotReleaseOtherOwner(t *testing.T) {
	tests := map[string]struct {
		panics bool
	}{
		"error: handler ignores cancelled reacquisition": {},
		"error: handler panics without reacquiring":      {panics: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			inBody := make(chan struct{})
			otherEntered := make(chan struct{})
			releaseOther := make(chan struct{})
			otherDone := make(chan error, 1)
			var order []string
			h := &mutationHook{onRequest: func(ctx context.Context, _ *flow.HTTPFlow) error {
				order = append(order, "first")
				next, err := Concurrent(ctx, func(context.Context) error {
					close(inBody)
					awaitMutation(t, otherEntered)
					cancel()
					if tt.panics {
						panic("cancelled handler")
					}
					return nil
				})
				if frameFrom(next) != nil || !errors.Is(err, context.Canceled) {
					t.Errorf("reacquisition frame = %v, error = %v", frameFrom(next), err)
				}
				return nil
			}, onUpdate: func(context.Context, []flow.Flow) error {
				order = append(order, "update")
				return nil
			}}
			second := &namedMutationHook{name: "second", mutationHook: &mutationHook{onRequest: func(context.Context, *flow.HTTPFlow) error {
				order = append(order, "second")
				return nil
			}}}
			first := &namedMutationHook{mutationHook: h, name: "first", onAddons: func() {
				if ctx.Err() != nil {
					t.Error("sub-addon traversal ran after cancelled reacquisition")
				}
			}}
			if err := e.m.Add(t.Context(), first, second); err != nil {
				t.Fatal(err)
			}
			go func() {
				awaitMutation(t, inBody)
				otherDone <- e.m.Do(t.Context(), func(context.Context) error {
					close(otherEntered)
					<-releaseOther
					return nil
				})
			}()
			result := make(chan error, 1)
			go func() {
				result <- e.m.HookFunc(ctx, nil, RequestHook{Flow: flow.NewHTTPFlow(nil, nil, true)}, func(context.Context) {
					order = append(order, "finish")
				})
			}()
			err := awaitMutation(t, result)
			if !errors.Is(err, context.Canceled) {
				t.Errorf("HookFunc = %v, want context.Canceled", err)
			}
			if diff := gocmp.Diff([]string{"first"}, order); diff != "" {
				t.Errorf("hook order (-want +got):\n%s", diff)
			}
			close(releaseOther)
			if err := awaitMutation(t, otherDone); err != nil {
				t.Fatal(err)
			}
			if err := e.m.Do(t.Context(), func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
		})
	}
}
