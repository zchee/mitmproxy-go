// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxyserver

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

func TestProxyServerClose(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"never_started": {run: func(t *testing.T) {
			_, ps, _, _ := fixture(t, false)
			for range 2 {
				if err := ps.Close(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if err := ps.SetupServers(t.Context()); !errors.Is(err, context.Canceled) {
				t.Fatalf("setup after close: %v", err)
			}
			if len(ps.ListenAddrs()) != 0 {
				t.Fatal("closed server opened a listener")
			}
		}},
		"running": {run: func(t *testing.T) {
			m, ps, _, _ := fixture(t, true)
			if err := ps.SetupServers(t.Context()); err != nil {
				t.Fatal(err)
			}
			addresses := ps.ListenAddrs()
			if len(addresses) != 1 {
				t.Fatalf("running listeners=%v", addresses)
			}
			if err := m.Do(t.Context(), ps.Done); err != nil {
				t.Fatal(err)
			}
			if err := ps.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			for _, address := range addresses {
				listener, err := net.Listen("tcp4", address.String())
				if err != nil {
					t.Fatalf("listener not released when Close returned: %v", err)
				}
				if err := listener.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := ps.Close(t.Context()); err != nil {
				t.Fatalf("repeat close: %v", err)
			}
		}},
		"startup_failure": {run: func(t *testing.T) {
			m, ps, _, _ := fixture(t, false)
			occupied, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := occupied.Close(); err != nil {
					t.Error(err)
				}
			}()
			port := occupied.Addr().(*net.TCPAddr).Port
			update(t, m, map[string]any{"listen_port": new(port)})
			if err := ps.SetupServers(t.Context()); err != nil {
				t.Fatal(err)
			}
			if len(ps.ListenAddrs()) != 0 {
				t.Fatal("bind failure published a listener")
			}
			if err := ps.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			probe, err := net.Listen("tcp4", occupied.Addr().String())
			if err == nil {
				_ = probe.Close()
				t.Fatal("Close released another owner's listener")
			}
		}},
		"context_bound": {run: func(t *testing.T) {
			m, ps, _, _ := fixture(t, false)
			if err := ps.SetupServers(t.Context()); err != nil {
				t.Fatal(err)
			}
			ps.updateMu.Lock()
			locked := true
			defer func() {
				if locked {
					ps.updateMu.Unlock()
				}
			}()
			if err := m.Do(t.Context(), ps.Done); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := ps.Close(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("blocked worker close=%v", err)
			}
			select {
			case <-ps.stopped:
				t.Fatal("Close claimed a blocked worker had joined")
			default:
			}
			ps.updateMu.Unlock()
			locked = false
			if err := ps.Close(t.Context()); err != nil {
				t.Fatalf("later close did not join: %v", err)
			}
		}},
		"concurrent_close_setup": {run: func(t *testing.T) {
			_, ps, _, _ := fixture(t, false)
			var workers sync.WaitGroup
			for i := range 16 {
				workers.Go(func() {
					if i%2 == 0 {
						if err := ps.SetupServers(t.Context()); err != nil && !errors.Is(err, context.Canceled) {
							t.Error(err)
						}
					} else if err := ps.Close(t.Context()); err != nil {
						t.Error(err)
					}
				})
			}
			workers.Wait()
			if err := ps.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if len(ps.ListenAddrs()) != 0 {
				t.Fatal("listener survived concurrent setup/close")
			}
		}},
	}
	for name, tt := range tests {
		t.Run(name, tt.run)
	}
}
