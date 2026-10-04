// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package addon_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

func newManager(t *testing.T, addons ...any) *addon.Manager {
	t.Helper()
	m := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{Logger: slog.New(slog.DiscardHandler)})
	t.Cleanup(m.Close)
	if err := m.Add(t.Context(), addons...); err != nil {
		t.Fatalf("Add: %v", err)
	}
	return m
}

// newRecorder registers a Recorder and forgets its load call.
func newRecorder(t *testing.T) (*addon.Manager, *addontest.Recorder) {
	t.Helper()
	r := &addontest.Recorder{}
	m := newManager(t, r)
	r.Reset()
	return m, r
}

// hookArgs builds one value of every hook, each with a distinct argument.
func hookArgs() []struct {
	hook addon.Hook
	arg  any
} {
	client := connection.NewClient(connection.Address{Host: "127.0.0.1", Port: 50000}, connection.Address{Host: "127.0.0.1", Port: 8080}, 1)
	server := &connection.Server{}
	hctx := &hookdata.Context{Client: client, Server: server}
	httpFlow := flow.NewHTTPFlow(client, server, true)
	tcpFlow := flow.NewTCPFlow(client, server, true)
	udpFlow := flow.NewUDPFlow(client, server, true)
	dnsFlow := flow.NewDNSFlow(client, server, true)
	tlsData := &hookdata.TLS{Conn: &client.Connection, Context: hctx}
	quicData := &hookdata.QUICTLS{Conn: &server.Connection, Context: hctx}
	serverConn := &hookdata.ServerConnection{Server: server, Client: client}
	nextLayer := &hookdata.NextLayer{Context: hctx}
	socks := &hookdata.Socks5Auth{Client: client, Username: "user"}
	hello := &hookdata.ClientHello{Context: hctx}
	loader := &addon.Loader{}
	updated := map[string]struct{}{"anticache": {}}
	entry := addon.LogEntry{Msg: "hello", Level: addon.LevelAlert}
	flows := []flow.Flow{httpFlow}

	return []struct {
		hook addon.Hook
		arg  any
	}{
		{addon.LoadHook{Loader: loader}, loader},
		{addon.ConfigureHook{Updated: updated}, updated},
		{addon.RunningHook{}, nil},
		{addon.DoneHook{}, nil},
		{addon.UpdateHook{Flows: flows}, flows},
		{addon.AddLogHook{Entry: entry}, entry},
		{addon.NextLayerHook{Data: nextLayer}, nextLayer},
		{addon.ClientConnectedHook{Client: client}, client},
		{addon.ClientDisconnectedHook{Client: client}, client},
		{addon.ServerConnectHook{Data: serverConn}, serverConn},
		{addon.ServerConnectedHook{Data: serverConn}, serverConn},
		{addon.ServerDisconnectedHook{Data: serverConn}, serverConn},
		{addon.ServerConnectErrorHook{Data: serverConn}, serverConn},
		{addon.Socks5AuthHook{Data: socks}, socks},
		{addon.RequestHeadersHook{Flow: httpFlow}, httpFlow},
		{addon.RequestHook{Flow: httpFlow}, httpFlow},
		{addon.ResponseHeadersHook{Flow: httpFlow}, httpFlow},
		{addon.ResponseHook{Flow: httpFlow}, httpFlow},
		{addon.ErrorHook{Flow: httpFlow}, httpFlow},
		{addon.HTTPConnectHook{Flow: httpFlow}, httpFlow},
		{addon.HTTPConnectUpstreamHook{Flow: httpFlow}, httpFlow},
		{addon.HTTPConnectedHook{Flow: httpFlow}, httpFlow},
		{addon.HTTPConnectErrorHook{Flow: httpFlow}, httpFlow},
		{addon.WebSocketStartHook{Flow: httpFlow}, httpFlow},
		{addon.WebSocketMessageHook{Flow: httpFlow}, httpFlow},
		{addon.WebSocketEndHook{Flow: httpFlow}, httpFlow},
		{addon.TCPStartHook{Flow: tcpFlow}, tcpFlow},
		{addon.TCPMessageHook{Flow: tcpFlow}, tcpFlow},
		{addon.TCPEndHook{Flow: tcpFlow}, tcpFlow},
		{addon.TCPErrorHook{Flow: tcpFlow}, tcpFlow},
		{addon.UDPStartHook{Flow: udpFlow}, udpFlow},
		{addon.UDPMessageHook{Flow: udpFlow}, udpFlow},
		{addon.UDPEndHook{Flow: udpFlow}, udpFlow},
		{addon.UDPErrorHook{Flow: udpFlow}, udpFlow},
		{addon.DNSRequestHook{Flow: dnsFlow}, dnsFlow},
		{addon.DNSResponseHook{Flow: dnsFlow}, dnsFlow},
		{addon.DNSErrorHook{Flow: dnsFlow}, dnsFlow},
		{addon.TLSClientHelloHook{Data: hello}, hello},
		{addon.TLSStartClientHook{Data: tlsData}, tlsData},
		{addon.TLSStartServerHook{Data: tlsData}, tlsData},
		{addon.TLSEstablishedClientHook{Data: tlsData}, tlsData},
		{addon.TLSEstablishedServerHook{Data: tlsData}, tlsData},
		{addon.TLSFailedClientHook{Data: tlsData}, tlsData},
		{addon.TLSFailedServerHook{Data: tlsData}, tlsData},
		{addon.QUICStartClientHook{Data: quicData}, quicData},
		{addon.QUICStartServerHook{Data: quicData}, quicData},
	}
}

// sameArg compares pointers and slices of flows by identity and other values
// by equality.
func sameArg(got, want any) bool {
	switch w := want.(type) {
	case map[string]struct{}:
		g, ok := got.(map[string]struct{})
		return ok && cmp.Equal(g, w)
	case []flow.Flow:
		g, ok := got.([]flow.Flow)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if g[i] != w[i] {
				return false
			}
		}
		return true
	default:
		return got == want
	}
}

// TestHooksReachHandlers dispatches each of the 46 hooks with Hook and
// checks that the handler runs once with the hook's argument, followed by
// update with the flow for the 23 hooks that carry one.
func TestHooksReachHandlers(t *testing.T) {
	cases := hookArgs()
	if len(cases) != 46 {
		t.Fatalf("%d hooks under test, want mitmproxy's 46", len(cases))
	}
	flowHooks := 0
	for _, c := range cases {
		t.Run("success: "+c.hook.Name(), func(t *testing.T) {
			m, r := newRecorder(t)
			if err := m.Hook(t.Context(), c.hook); err != nil {
				t.Fatalf("Hook: %v", err)
			}
			calls := r.Calls()
			want := []string{c.hook.Name()}
			f, isFlow := c.arg.(flow.Flow)
			if isFlow {
				want = append(want, "update")
			}
			if diff := cmp.Diff(want, r.Hooks()); diff != "" {
				t.Fatalf("hooks received (-want +got):\n%s", diff)
			}
			if !sameArg(calls[0].Arg, c.arg) {
				t.Errorf("%s received %#v, want %#v", c.hook.Name(), calls[0].Arg, c.arg)
			}
			if isFlow && !sameArg(calls[1].Arg, []flow.Flow{f}) {
				t.Errorf("update after %s received %#v, want the hook's flow", c.hook.Name(), calls[1].Arg)
			}
		})
		if _, ok := c.arg.(flow.Flow); ok {
			flowHooks++
		}
	}
	if flowHooks != 23 {
		t.Errorf("%d flow hooks, want 23", flowHooks)
	}
}

// TestTriggerFiresNoUpdate checks that Trigger, mitmproxy's sync trigger,
// does not follow a flow hook with update.
func TestTriggerFiresNoUpdate(t *testing.T) {
	m, r := newRecorder(t)
	f := flow.NewHTTPFlow(connection.NewClient(connection.Address{}, connection.Address{}, 0), &connection.Server{}, true)
	if err := m.Trigger(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if diff := cmp.Diff([]string{"request"}, r.Hooks()); diff != "" {
		t.Errorf("hooks received (-want +got):\n%s", diff)
	}
}

// requestAddon returns err from its request handler.
type requestAddon struct{ err error }

func (a *requestAddon) Request(context.Context, *flow.HTTPFlow) error { return a.err }

func TestHookUpdateRules(t *testing.T) {
	tests := map[string]struct {
		err        error
		flow       bool
		wantHooks  []string
		wantOptErr bool
	}{
		"success: update follows a halted hook": {
			err:       fmt.Errorf("stop here: %w", addon.ErrAddonHalt),
			flow:      true,
			wantHooks: []string{"update"},
		},
		"success: update follows a hook whose handler failed": {
			err:       errors.New("boom"),
			flow:      true,
			wantHooks: []string{"request", "update"},
		},
		"error: an options error suppresses update": {
			err:        options.Errorf("bad"),
			flow:       true,
			wantOptErr: true,
		},
		"success: a hook without a flow fires no update": {
			flow:      false,
			wantHooks: []string{"request"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := &addontest.Recorder{}
			m := newManager(t, &requestAddon{err: tt.err}, r)
			r.Reset()
			var f *flow.HTTPFlow
			if tt.flow {
				f = flow.NewHTTPFlow(connection.NewClient(connection.Address{}, connection.Address{}, 0), &connection.Server{}, true)
			}
			err := m.Hook(t.Context(), addon.RequestHook{Flow: f})
			if _, isOpt := errors.AsType[*options.OptionsError](err); isOpt != tt.wantOptErr || (err != nil && !tt.wantOptErr) {
				t.Fatalf("Hook error = %v, want an options error: %v", err, tt.wantOptErr)
			}
			if diff := cmp.Diff(tt.wantHooks, r.Hooks(), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("hooks the recorder received (-want +got):\n%s", diff)
			}
		})
	}
}

// blockingAddon releases the dispatch lock in its request handler until
// the test lets it continue.
type blockingAddon struct {
	entered chan struct{}
	proceed chan struct{}
	err     chan error
}

func (a *blockingAddon) Request(ctx context.Context, f *flow.HTTPFlow) error {
	if f.Comment != "blocking" {
		return nil
	}
	_, err := addon.Concurrent(ctx, func(context.Context) error {
		close(a.entered)
		<-a.proceed
		return nil
	})
	a.err <- err
	return nil
}

// TestConcurrentInFlowHook releases the lock in one flow's request hook
// while another flow's request hook, and its update, run to completion.
func TestConcurrentInFlowHook(t *testing.T) {
	b := &blockingAddon{entered: make(chan struct{}), proceed: make(chan struct{}), err: make(chan error, 1)}
	r := &addontest.Recorder{}
	m := newManager(t, b, r)
	r.Reset()

	newFlow := func(comment string) *flow.HTTPFlow {
		f := flow.NewHTTPFlow(connection.NewClient(connection.Address{}, connection.Address{}, 0), &connection.Server{}, true)
		f.Comment = comment
		return f
	}
	slow, fast := newFlow("blocking"), newFlow("fast")

	slowDone := make(chan error, 1)
	go func() { slowDone <- m.Hook(t.Context(), addon.RequestHook{Flow: slow}) }()

	select {
	case <-b.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the blocking handler did not reach Concurrent")
	}
	fastDone := make(chan error, 1)
	go func() { fastDone <- m.Hook(t.Context(), addon.RequestHook{Flow: fast}) }()
	select {
	case err := <-fastDone:
		if err != nil {
			t.Fatalf("Hook(fast): %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("another flow's hook did not run while the first was in Concurrent")
	}
	close(b.proceed)
	select {
	case err := <-slowDone:
		if err != nil {
			t.Fatalf("Hook(slow): %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the blocking flow's hook did not finish")
	}
	if err := <-b.err; err != nil {
		t.Errorf("Concurrent in a request hook dispatched with Hook: %v", err)
	}

	var order []string
	for _, c := range r.Calls() {
		var f *flow.HTTPFlow
		if c.Hook == "update" {
			f = c.Arg.([]flow.Flow)[0].(*flow.HTTPFlow)
		} else {
			f = c.Arg.(*flow.HTTPFlow)
		}
		order = append(order, c.Hook+" "+f.Comment)
	}
	want := []string{"request fast", "update fast", "request blocking", "update blocking"}
	if diff := cmp.Diff(want, order); diff != "" {
		t.Errorf("hooks the recorder received (-want +got):\n%s", diff)
	}
}
