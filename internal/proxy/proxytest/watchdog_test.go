// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest_test

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

// interceptFirst intercepts the first TCP message it sees and publishes the
// intercepted flow. Later messages, including the echoed response, pass.
// Handlers run under dispatch, which serializes the done flag.
type interceptFirst struct {
	done  bool
	flows chan *flow.TCPFlow
}

func (a *interceptFirst) TCPMessage(_ context.Context, f *flow.TCPFlow) error {
	if a.done {
		return nil
	}
	a.done = true
	f.Intercept()
	a.flows <- f
	return nil
}

func TestInterceptionSuspendsWatchdog(t *testing.T) {
	origin := proxytest.StartEchoOrigin(t)
	addon := &interceptFirst{flows: make(chan *flow.TCPFlow, 1)}
	p := proxytest.Start(t,
		proxytest.WithAddons(addon),
		proxytest.WithOptions(map[string]any{
			"mode":        []string{"reverse:tcp://" + origin.Addr},
			"tcp_timeout": 1,
		}),
	)
	client := dial(t, p.Addr)
	if _, err := io.WriteString(client, "ping"); err != nil {
		t.Fatal(err)
	}
	f := receive(t, addon.flows)
	// Hold the interception well past the one-second inactivity timeout:
	// time spent waiting for the user must not count as inactivity.
	time.Sleep(4 * time.Second)
	if err := p.Master.Do(t.Context(), func(context.Context) error {
		f.Resume()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("ping"))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("intercepted connection expired instead of completing: %v", err)
	}
	if diff := gocmp.Diff("ping", string(buf)); diff != "" {
		t.Fatal(diff)
	}
	_ = client.Close()
	awaitHook(t, p, "tcp_end")
}

// holdFlows intercepts the first flow's first message and blocks the second
// flow's first message inside its hook handler until released. Every other
// message passes.
type holdFlows struct {
	intercepted *flow.TCPFlow
	held        *flow.TCPFlow

	flows   chan *flow.TCPFlow
	entered chan struct{}
	release chan struct{}
}

func (a *holdFlows) TCPMessage(ctx context.Context, f *flow.TCPFlow) error {
	switch {
	case a.intercepted == nil:
		a.intercepted = f
		a.flows <- f
		f.Intercept()
	case a.held == nil && f != a.intercepted:
		a.held = f
		close(a.entered)
		select {
		case <-a.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func TestWatchdogTCPHookAndInterceptionIsolation(t *testing.T) {
	origin := proxytest.StartEchoOrigin(t)
	addon := &holdFlows{flows: make(chan *flow.TCPFlow, 1), entered: make(chan struct{}), release: make(chan struct{})}
	releaseHeld := sync.OnceFunc(func() { close(addon.release) })
	t.Cleanup(releaseHeld)
	p := proxytest.Start(t,
		proxytest.WithAddons(addon),
		proxytest.WithOptions(map[string]any{
			"mode":        []string{"reverse:tcp://" + origin.Addr},
			"tcp_timeout": 1,
		}),
	)
	idle := dial(t, p.Addr)
	// Finish the idle connection's startup hooks before another hook can hold
	// dispatch; waiting for dispatch suspends that connection's watchdog.
	awaitHook(t, p, "server_connected")
	intercepted := dial(t, p.Addr)
	if _, err := io.WriteString(intercepted, "intercepted"); err != nil {
		t.Fatal(err)
	}
	f := receive(t, addon.flows)
	inHook := dial(t, p.Addr)
	if _, err := io.WriteString(inHook, "in hook"); err != nil {
		t.Fatal(err)
	}
	receive(t, addon.entered)
	// All three connections now rest past the one-second timeout: only the
	// idle one may expire while hook execution and interception are held.
	time.Sleep(2 * time.Second)
	if _, err := idle.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("idle connection read = %v, want watchdog closure", err)
	}
	releaseHeld()
	buf := make([]byte, len("in hook"))
	if _, err := io.ReadFull(inHook, buf); err != nil {
		t.Fatalf("connection held in a hook expired: %v", err)
	}
	if diff := gocmp.Diff("in hook", string(buf)); diff != "" {
		t.Fatal(diff)
	}
	if err := p.Master.Do(t.Context(), func(context.Context) error {
		f.Resume()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, len("intercepted"))
	if _, err := io.ReadFull(intercepted, buf); err != nil {
		t.Fatalf("intercepted connection expired: %v", err)
	}
	_ = inHook.Close()
	_ = intercepted.Close()
}
