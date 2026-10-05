// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/options"
	"github.com/zchee/mitmproxy-go/tcp"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(30 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("operation did not complete:\n%s", buf[:n])
		var zero T
		return zero
	}
}

type runnerAddon struct {
	request func(context.Context, *flow.HTTPFlow) error
	update  func(context.Context, []flow.Flow) error
}

func (a *runnerAddon) Request(ctx context.Context, f *flow.HTTPFlow) error { return a.request(ctx, f) }

func (a *runnerAddon) Update(ctx context.Context, flows []flow.Flow) error {
	if a.update != nil {
		return a.update(ctx, flows)
	}
	return nil
}

func newHookRunner(t *testing.T, addons ...any) *HookRunner {
	t.Helper()
	m := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
	t.Cleanup(m.Close)
	if err := m.Add(t.Context(), addons...); err != nil {
		t.Fatal(err)
	}
	return &HookRunner{Manager: m}
}

func TestCapturePartialHTTP(t *testing.T) {
	f := flow.NewHTTPFlow(connection.NewClient(connection.Address{}, connection.Address{}, 1), connection.NewServer(nil), true)
	f.Request = &httpmsg.Request{}
	f.Error = flow.NewError("failure")
	s := capture(f)
	if s.Request == nil || s.Response != nil {
		t.Fatal("partial HTTP state lost")
	}
	f.ClientConn.ALPN = []byte("h2")
	f.ServerConn.SNI = new("changed")
	f.Error.Msg = "changed"
	if s.Client.ALPN != nil || s.Server.SNI != nil || s.Error.Msg != "failure" {
		t.Fatal("snapshot aliases live metadata")
	}
}

func TestCaptureCurrentTCPMessage(t *testing.T) {
	f := flow.NewTCPFlow(nil, nil, true)
	f.Messages = []*tcp.Message{nil, tcp.NewMessage(true, []byte("current"))}
	s := capture(f)
	f.Messages[1].Content[0] = 'X'
	if s.NumMessages != 2 || string(s.LastMessage.Content) != "current" {
		t.Fatal("current message not cloned")
	}
}

func TestHookRunnerSnapshotAfterUpdate(t *testing.T) {
	f := flow.NewHTTPFlow(nil, nil, true)
	f.Request = &httpmsg.Request{}
	r := newHookRunner(t, &runnerAddon{
		request: func(ctx context.Context, f *flow.HTTPFlow) error {
			_, err := addon.Concurrent(ctx, func(context.Context) error { return nil })
			return err
		},
		update: func(_ context.Context, _ []flow.Flow) error {
			f.Request.Method = "UPDATED"
			return nil
		},
	})
	var calls []string
	r.Disarm = func() { calls = append(calls, "disarm") }
	r.Rearm = func() { calls = append(calls, "rearm") }
	s, err := r.Fire(t.Context(), addon.RequestHook{Flow: f})
	if err != nil {
		t.Fatal(err)
	}
	f.Request.Method = "CHANGED"
	if string(s.Request.Method) != "UPDATED" {
		t.Fatalf("snapshot before update or not cloned: %q", s.Request.Method)
	}
	if diff := gocmp.Diff([]string{"disarm", "rearm"}, calls); diff != "" {
		t.Fatal(diff)
	}
}

func TestHookRunnerInterceptAndCancel(t *testing.T) {
	tests := map[string]struct{ cancel bool }{"resume": {}, "cancel": {true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := flow.NewHTTPFlow(nil, nil, true)
			entered := make(chan struct{})
			r := newHookRunner(t, &runnerAddon{request: func(context.Context, *flow.HTTPFlow) error {
				f.Intercept()
				close(entered)
				return nil
			}})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := r.Fire(ctx, addon.RequestHook{Flow: f}); done <- err }()
			await(t, entered)
			if err := r.Manager.Do(t.Context(), func(context.Context) error {
				if tt.cancel {
					cancel()
				} else {
					f.Resume()
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			err := await(t, done)
			if tt.cancel && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel: %v", err)
			}
			if !tt.cancel && err != nil {
				t.Fatal(err)
			}
		})
	}
}
