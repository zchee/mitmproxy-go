// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
)

func TestUDPRelayTerminalInterception(t *testing.T) {
	tests := map[string]struct {
		shutdown, cancelOpen, openError bool
	}{
		"connections close":   {},
		"proxy shutdown":      {shutdown: true},
		"cancel pending open": {shutdown: true, cancelOpen: true},
		"open failure":        {openError: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			opening := make(chan struct{})
			terminal := func(ctx context.Context, f *flow.UDPFlow) error {
				if ctx.Err() != nil || ctx.Done() != nil {
					t.Error("terminal hook context is cancellable")
				}
				if !f.Live {
					t.Error("terminal hook must observe live flow before cleanup")
				}
				f.Intercept()
				return nil
			}
			a := &udpRelayAddon{end: terminal, failed: terminal}
			if test.openError {
				a.connect = func(_ context.Context, d *hookdata.ServerConnection) error {
					d.Server.Error = new("connection refused")
					return nil
				}
			} else if test.cancelOpen {
				a.connect = func(ctx context.Context, _ *hookdata.ServerConnection) error {
					close(opening)
					_, err := addon.Concurrent(ctx, func(ctx context.Context) error {
						<-ctx.Done()
						return ctx.Err()
					})
					return err
				}
			}
			f := startUDPRelay(t, udpRelayConfig{first: []byte("first"), addon: a, ctx: ctx})
			current := await(t, f.flow)
			want := []string{"udp_start"}
			if test.cancelOpen {
				await(t, opening)
			} else if !test.openError {
				requireDatagram(t, f.origin, []byte("first"))
				want = append(want, "udp_message")
			}
			if test.shutdown {
				cancel()
			} else if !test.openError {
				f.connections.Close()
			}
			err := await(t, f.done)
			if test.openError {
				if err == nil {
					t.Fatal("open failure was lost")
				}
				want = append(want, "udp_error")
			} else {
				if err != nil {
					t.Fatal(err)
				}
				want = append(want, "udp_end")
			}
			if diff := gocmp.Diff(want, udpHooks(f.recorder)); diff != "" {
				t.Fatal(diff)
			}
			if err := f.manager.Do(t.Context(), func(context.Context) error {
				if current.Live || current.Intercepted() {
					t.Error("terminal flow is still live or intercepted")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if f.connections.Len() != 0 || f.tuple.Context().Err() == nil {
				t.Fatal("finished tuple was not evicted")
			}
		})
	}
}
