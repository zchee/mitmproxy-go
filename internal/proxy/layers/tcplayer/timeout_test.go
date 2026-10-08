// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tcplayer

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

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
	tests := map[string]struct {
		cancel bool
		hook   string
		yield  bool
	}{
		"cancelled connection":             {cancel: true, hook: "tcp_end"},
		"opening failure":                  {hook: "tcp_error"},
		"cancelled yielding terminal hook": {cancel: true, hook: "tcp_end", yield: true},
		"failed yielding terminal hook":    {hook: "tcp_error", yield: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				entered, returned := make(chan struct{}), make(chan error, 1)
				const timeout = time.Second
				var deadline time.Time
				terminal := func(ctx context.Context, f *flow.TCPFlow) error {
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
				a := &observer{end: terminal, failed: terminal}
				manager := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
				defer manager.Close()
				if err := manager.Add(t.Context(), a); err != nil {
					t.Fatal(err)
				}
				f := flow.NewTCPFlow(connection.NewClient(connection.Address{}, connection.Address{}, 1), connection.NewServer(nil), true)
				l := &tcpLayer{flow: f, terminalHookTimeout: timeout}
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
					Pool: openPool{open: func(context.Context, *connection.Server, layer.OpenOptions) (layer.Conn, *connection.Server, error) {
						if test.cancel {
							cancel()
							return nil, nil, context.Canceled
						}
						return nil, nil, openErr
					}},
				}
				done := make(chan error, 1)
				go func() { done <- l.Run(ctx, c) }()
				await(t, entered)
				synctest.Wait()
				if diff := gocmp.Diff(timeout, time.Until(deadline)); diff != "" {
					t.Fatal(diff)
				}
				time.Sleep(timeout)
				if err := await(t, returned); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("terminal addon error = %v", err)
				}
				if err := await(t, cleanup); err != nil {
					t.Fatalf("cleanup context error = %v, want active context", err)
				}
				wantErr := openErr
				if test.cancel {
					wantErr = context.Canceled
				}
				if err := await(t, done); !errors.Is(err, wantErr) {
					t.Fatalf("owner error = %v, want %v", err, wantErr)
				}
				if diff := gocmp.Diff([]string{"tcp_start", test.hook}, a.events); diff != "" {
					t.Fatal(diff)
				}
				if f.Live || f.Intercepted() {
					t.Fatal("finished flow remains live or intercepted")
				}
			})
		})
	}
}
