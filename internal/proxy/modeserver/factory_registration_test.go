// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
)

func TestRegisteredListenerFactorySnapshot(t *testing.T) {
	key := ListenerKey{Scheme: "factory-snapshot-test", Transport: connection.UDP}
	t.Cleanup(func() { listenerRegistry.Delete(key) })
	calls := make(chan string, 4)
	factory := func(name string) ListenerFactory {
		return func(_ context.Context, socket net.PacketConn, _ PacketHandler) (io.Closer, error) {
			calls <- name
			return socket, nil
		}
	}
	RegisterListenerFactory(key, factory("registered"))
	cfg, _, _ := fixture(t)
	registered := makeInstance(t, "reverse:udp://example.test:443@127.0.0.1:0", cfg)
	cfg.ListenerFactories = map[ListenerKey]ListenerFactory{key: factory("override")}
	overridden := makeInstance(t, "reverse:udp://example.test:443@127.0.0.1:0", cfg)
	delete(cfg.ListenerFactories, key)
	listenerRegistry.Delete(key)
	tests := map[string]struct {
		instance *Instance
		want     string
	}{
		"default copied":           {registered, "registered"},
		"explicit override copied": {overridden, "override"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Construction validates real mode schemes; factory selection uses
			// this row's private key without changing the captured snapshots.
			mode := tt.instance.mode.(modespec.ReverseMode)
			mode.Scheme = key.Scheme
			tt.instance.mode = mode
			selected, err := tt.instance.packetFactory()
			if err != nil {
				t.Fatal(err)
			}
			socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = socket.Close() }()
			closer, err := selected(t.Context(), socket, nil)
			if err != nil {
				t.Fatal(err)
			}
			if closer != socket || await(t, calls) != tt.want {
				t.Fatal("factory snapshot or override differs")
			}
		})
	}
}

func TestListenerFactoryRegistrationRejectsInvalid(t *testing.T) {
	factory := func(_ context.Context, socket net.PacketConn, _ PacketHandler) (io.Closer, error) { return socket, nil }
	tests := map[string]struct {
		key       ListenerKey
		factory   ListenerFactory
		duplicate bool
	}{
		"nil":              {ListenerKey{"factory-registration-test", connection.UDP}, nil, false},
		"duplicate":        {ListenerKey{"factory-registration-test", connection.UDP}, factory, true},
		"empty scheme":     {ListenerKey{"", connection.UDP}, factory, false},
		"stream transport": {ListenerKey{"factory-registration-test", connection.TCP}, factory, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { listenerRegistry.Delete(tt.key) })
			if tt.duplicate {
				RegisterListenerFactory(tt.key, tt.factory)
			}
			defer func() {
				if recover() == nil {
					t.Fatal("invalid registration did not panic")
				}
			}()
			RegisterListenerFactory(tt.key, tt.factory)
		})
	}
}
