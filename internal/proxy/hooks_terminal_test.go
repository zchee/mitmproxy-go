// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
)

type terminalInterceptor struct{}

func (*terminalInterceptor) TCPEnd(_ context.Context, f *flow.TCPFlow) error {
	f.Intercept()
	return nil
}

func (*terminalInterceptor) TCPError(_ context.Context, f *flow.TCPFlow) error {
	f.Intercept()
	return nil
}

func (*terminalInterceptor) UDPEnd(_ context.Context, f *flow.UDPFlow) error {
	f.Intercept()
	return nil
}

func (*terminalInterceptor) UDPError(_ context.Context, f *flow.UDPFlow) error {
	f.Intercept()
	return nil
}

func TestHookRunnerTerminalInterception(t *testing.T) {
	tests := map[string]struct {
		hook func() addon.Hook
	}{
		"tcp end":   {hook: func() addon.Hook { return addon.TCPEndHook{Flow: flow.NewTCPFlow(nil, nil, true)} }},
		"tcp error": {hook: func() addon.Hook { return addon.TCPErrorHook{Flow: flow.NewTCPFlow(nil, nil, true)} }},
		"udp end":   {hook: func() addon.Hook { return addon.UDPEndHook{Flow: flow.NewUDPFlow(nil, nil, true)} }},
		"udp error": {hook: func() addon.Hook { return addon.UDPErrorHook{Flow: flow.NewUDPFlow(nil, nil, true)} }},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r := newHookRunner(t, new(terminalInterceptor))
			hook := test.hook()
			f := addon.HookFlow(hook)
			f.Common().Intercept()
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			done := make(chan error, 1)
			go func() {
				_, err := r.Fire(context.WithoutCancel(ctx), hook)
				done <- err
			}()
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
			if f.Common().Intercepted() {
				t.Fatal("terminal hook retained interception")
			}
		})
	}
}

func TestHookRunnerHTTPResponseStillIntercepts(t *testing.T) {
	f := flow.NewHTTPFlow(nil, nil, true)
	entered := make(chan struct{})
	r := newHookRunner(t, &runnerAddon{response: func(context.Context, *flow.HTTPFlow) error {
		f.Intercept()
		close(entered)
		return nil
	}})
	done := make(chan error, 1)
	go func() {
		_, err := r.Fire(t.Context(), addon.ResponseHook{Flow: f})
		done <- err
	}()
	await(t, entered)
	if err := r.Manager.Do(t.Context(), func(context.Context) error {
		if !f.Intercepted() {
			t.Error("HTTP response was automatically resumed")
		}
		select {
		case err := <-done:
			t.Fatalf("response completed before Resume: %v", err)
		default:
		}
		f.Resume()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}
