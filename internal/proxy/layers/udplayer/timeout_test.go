// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package udplayer

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"testing/synctest"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/options"
)

func TestTerminalHookTimeout(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	tests := map[string]struct {
		cancel bool
		hook   string
		yield  bool
	}{
		"cancelled connection":             {cancel: true, hook: "udp_end"},
		"opening failure":                  {hook: "udp_error"},
		"cancelled yielding terminal hook": {cancel: true, hook: "udp_end", yield: true},
		"failed yielding terminal hook":    {hook: "udp_error", yield: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				entered, returned := make(chan struct{}), make(chan error, 1)
				const timeout = time.Second
				var deadline time.Time
				terminal := func(ctx context.Context, f *flow.UDPFlow) error {
					var ok bool
					deadline, ok = ctx.Deadline()
					if !ok || ctx.Err() != nil || ctx.Done() == nil {
						t.Error("terminal hook must begin with an active cleanup deadline")
					}
					f.Intercept()
					close(entered)
					waitDeadline := func(ctx context.Context) error {
						<-ctx.Done()
						returned <- ctx.Err()
						return ctx.Err()
					}
					if test.yield {
						_, err := addon.Concurrent(ctx, waitDeadline)
						return err
					}
					return waitDeadline(ctx)
				}
				a := &terminalObserver{terminal: terminal}
				manager := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
				defer manager.Close()
				if err := manager.Add(t.Context(), a); err != nil {
					t.Fatal(err)
				}
				f := flow.NewUDPFlow(connection.NewClient(connection.Address{}, connection.Address{}, 1), connection.NewServer(nil), true)
				l := &udpLayer{flow: f, flowID: f.ID, terminalHookTimeout: timeout}
				openErr := errors.New("connection refused")
				cleanup := make(chan error, 1)
				c := &layer.Context{
					Data:  &hookdata.Context{Client: f.ClientConn, Server: f.ServerConn},
					Hooks: &proxy.HookRunner{Manager: manager},
					Do: func(ctx context.Context, fn func(context.Context) error) error {
						return manager.Do(ctx, func(ctx context.Context) error {
							err := fn(ctx)
							if !f.Live {
								if got, ok := ctx.Deadline(); !ok || got.Equal(deadline) || ctx.Err() != nil {
									t.Error("cleanup did not receive an active, distinct deadline")
								}
								if f.Intercepted() {
									t.Error("terminal cleanup retained interception")
								}
								cleanup <- ctx.Err()
							}
							return err
						})
					},
					OpenPackets: func(context.Context, *connection.Server) (layer.PacketTransport, *connection.Server, error) {
						if test.cancel {
							cancel()
							return nil, nil, context.Canceled
						}
						return nil, nil, openErr
					},
				}
				done := make(chan error, 1)
				go func() { done <- l.Run(ctx, c) }()
				awaitTerminal(t, entered)
				synctest.Wait()
				if diff := gocmp.Diff(timeout, time.Until(deadline)); diff != "" {
					t.Fatal(diff)
				}
				time.Sleep(timeout)
				if err := awaitTerminal(t, returned); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("terminal addon error = %v", err)
				}
				if err := awaitTerminal(t, cleanup); err != nil {
					t.Fatalf("cleanup context error = %v, want active context", err)
				}
				wantErr := openErr
				if test.cancel {
					wantErr = context.Canceled
				}
				if err := awaitTerminal(t, done); !errors.Is(err, wantErr) {
					t.Fatalf("owner error = %v, want %v", err, wantErr)
				}
				if diff := gocmp.Diff([]string{"udp_start", test.hook}, a.events); diff != "" {
					t.Fatal(diff)
				}
				if f.Live || f.Intercepted() {
					t.Fatal("finished flow remains live or intercepted")
				}
			})
		})
	}
}

type terminalObserver struct {
	events   []string
	terminal func(context.Context, *flow.UDPFlow) error
}

func (a *terminalObserver) UDPStart(context.Context, *flow.UDPFlow) error {
	a.events = append(a.events, "udp_start")
	return nil
}

func (a *terminalObserver) UDPEnd(ctx context.Context, f *flow.UDPFlow) error {
	a.events = append(a.events, "udp_end")
	return a.terminal(ctx, f)
}

func (a *terminalObserver) UDPError(ctx context.Context, f *flow.UDPFlow) error {
	a.events = append(a.events, "udp_error")
	return a.terminal(ctx, f)
}

func awaitTerminal[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(30 * time.Second):
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		t.Fatalf("terminal operation did not complete:\n%s", stack[:n])
		var zero T
		return zero
	}
}
