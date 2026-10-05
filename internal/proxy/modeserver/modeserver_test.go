// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/master"
)

// Upstream test_mode_servers.py coverage:
// test_make: TestMake; Python subclass checks and to_json have no Go counterpart.
// test_last_exception_and_running: TestLastErrorAndRunning.
// test_tcp_start_stop: TestTCPStartStop.
// test_tcp_timeout: TestTCPTimeout.
// test_tcp_start_error: TestTCPStartError.
// test_dual_stack: TestDualStack (TCP regular instead of unsupported DNS).
// test_invalid_protocol: not applicable; modespec.Mode has sealed implementations.
// test_transparent: unsupported original-destination mode, rejected by New.
// test_wireguard, test_wireguard_dual_stack, test_wireguard_generate_conf,
// test_wireguard_invalid_conf: require the unimplemented WireGuard server.
// test_udp_start_stop, test_udp_start_error, test_dns_start_stop: require UDP/DNS.
// test_tun_mode, test_tun_mode_mocked: require the unimplemented TUN backend.
// test_local_redirector, test_local_redirector_startup_err,
// test_multiple_local_redirectors, test_always_uses_current_instance: require
// the unimplemented local redirector backend.

func TestMake(t *testing.T) {
	cfg, _, _ := fixture(t)
	tests := map[string]struct{ supported bool }{
		"regular": {true}, "upstream:example.com": {true},
		"reverse:http://example.com": {true}, "reverse:https://example.com": {true},
		"reverse:tcp://example.com:1234": {true}, "reverse:tls://example.com:1234": {true},
		"transparent": {}, "socks5": {}, "wireguard": {}, "local": {}, "tun": {}, "dns": {},
		"reverse:udp://example.com:1234": {}, "reverse:dtls://example.com:1234": {},
		"reverse:quic://example.com:1234": {}, "reverse:http3://example.com": {},
		"reverse:dns://example.com": {},
	}
	for spec, tt := range tests {
		t.Run(spec, func(t *testing.T) {
			mode, err := modespec.Parse(spec)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := New(mode, cfg)
			if !tt.supported {
				want := "Proxy mode " + spec + " is not supported by mitmproxy-go yet."
				if err == nil || err.Error() != want {
					t.Fatalf("New: %v, want %q", err, want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(spec, instance.Mode().String()); diff != "" {
				t.Fatal(diff)
			}
			if instance.IsRunning() || instance.LastError() != nil || len(instance.ListenAddrs()) != 0 {
				t.Fatal("new instance unexpectedly running")
			}
		})
	}
}

func TestTCPStartStop(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	cfg, m, hooks := fixture(t)
	instance := makeInstance(t, "regular@127.0.0.1:0", cfg)
	if err := instance.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	addr := instance.ListenAddrs()[0]
	client, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if got := await(t, hooks.connected); got != instance.Mode().String() {
		t.Fatalf("mode = %q", got)
	}
	// Holding dispatch while Stop executes proves Stop does not join handlers.
	if err := m.Do(t.Context(), func(context.Context) error { return instance.Stop() }); err != nil {
		t.Fatal(err)
	}
	if instance.IsRunning() || len(instance.ListenAddrs()) != 0 {
		t.Fatal("listener remains published after Stop")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	await(t, hooks.disconnected)
	if _, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr.String()); err == nil {
		t.Fatal("stopped listener accepted a client")
	}
}

func TestLastErrorAndRunning(t *testing.T) {
	cfg, _, _ := fixture(t)
	instance := makeInstance(t, "regular@127.0.0.1:0", cfg)
	if err := instance.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !instance.IsRunning() || instance.LastError() != nil {
		t.Fatal("start state not published")
	}
	// A real listener already closed by its owner exercises the close-error path.
	if err := instance.state.Load().listeners[0].Close(); err != nil {
		t.Fatal(err)
	}
	err := instance.Stop()
	if !errors.Is(err, net.ErrClosed) || !errors.Is(instance.LastError(), net.ErrClosed) {
		t.Fatalf("Stop error = %v, LastError = %v", err, instance.LastError())
	}
	if instance.IsRunning() {
		t.Fatal("close failure retained running state")
	}
	if err := instance.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if instance.LastError() != nil {
		t.Fatal("successful restart retained error")
	}
}

func TestTCPStartError(t *testing.T) {
	cfg, _, _ := fixture(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := listener.Addr().(*net.TCPAddr).Port
	cfg.ListenHost, cfg.ListenPort = "127.0.0.1", &port
	tests := map[string]struct{ hint bool }{
		"regular": {true}, fmt.Sprintf("regular@127.0.0.1:%d", port): {},
	}
	for spec, tt := range tests {
		t.Run(spec, func(t *testing.T) {
			instance := makeInstance(t, spec, cfg)
			err := instance.Start(t.Context())
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("HTTP(S) proxy failed to listen on 127.0.0.1:%d", port)) {
				t.Fatalf("start error = %v", err)
			}
			wantHint := fmt.Sprintf("Try specifying a different port by using `--mode regular@%d`.", port+2)
			if strings.Contains(err.Error(), wantHint) != tt.hint {
				t.Fatalf("start error hint = %v, want hint %v", err, tt.hint)
			}
			if instance.LastError() != err || instance.IsRunning() {
				t.Fatal("bind failure state not published")
			}
		})
	}
}

func TestTCPTimeout(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	cfg, m, hooks := fixture(t)
	if err := m.Do(t.Context(), func(ctx context.Context) error { return m.Options.Update(ctx, map[string]any{"tcp_timeout": 0}) }); err != nil {
		t.Fatal(err)
	}
	instance := makeInstance(t, "regular@127.0.0.1:0", cfg)
	if err := instance.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("tcp", instance.ListenAddrs()[0].String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := client.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("idle read = %d, %v", n, err)
	}
	await(t, hooks.disconnected)
}

func TestDualStack(t *testing.T) {
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	_ = probe.Close()
	cfg, _, hooks := fixture(t)
	instance := makeInstance(t, "regular@0", cfg)
	if err := instance.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	addrs := instance.ListenAddrs()
	if len(addrs) != 2 || addrs[0].Port != addrs[1].Port || addrs[0].Port == 0 {
		t.Fatalf("dual-stack addresses = %v", addrs)
	}
	tests := map[string]struct{ host string }{"IPv4": {"127.0.0.1"}, "IPv6": {"::1"}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client, err := net.Dial("tcp", (connection.Address{Host: tt.host, Port: addrs[0].Port}).String())
			if err != nil {
				t.Fatal(err)
			}
			await(t, hooks.connected)
			_ = client.Close()
			await(t, hooks.disconnected)
		})
	}
	addrs[0].Host = "mutated"
	if instance.ListenAddrs()[0].Host == "mutated" {
		t.Fatal("ListenAddrs shares mutable storage")
	}
}

func TestDualStackPortCollision(t *testing.T) {
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	_ = probe.Close()
	cfg, _, _ := fixture(t)
	instance := makeInstance(t, "regular@0", cfg)
	listen := instance.listenTCP
	var occupied net.Listener
	instance.listenTCP = func(ctx context.Context, network, address string) (net.Listener, error) {
		listener, err := listen(ctx, network, address)
		if err == nil && network == "tcp4" {
			port := listener.Addr().(*net.TCPAddr).Port
			occupied, err = listen(ctx, "tcp6", fmt.Sprintf("[::]:%d", port))
			if err != nil {
				_ = listener.Close()
				return nil, err
			}
		}
		return listener, err
	}
	defer func() {
		if occupied != nil {
			_ = occupied.Close()
		}
	}()
	if err := instance.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	addrs := instance.ListenAddrs()
	if len(addrs) != 2 || addrs[0].Port == addrs[1].Port {
		t.Fatalf("fallback addresses = %v", addrs)
	}
}

func TestCanceledStart(t *testing.T) {
	cfg, _, _ := fixture(t)
	instance := makeInstance(t, "regular@127.0.0.1:0", cfg)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := instance.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Start = %v", err)
	}
	if instance.IsRunning() {
		t.Fatal("canceled Start opened listeners")
	}
}

type lifecycle struct {
	connected    chan string
	disconnected chan struct{}
}

func (l *lifecycle) ClientConnected(_ context.Context, c *connection.Client) error {
	l.connected <- c.ProxyMode
	return nil
}

func (l *lifecycle) ClientDisconnected(context.Context, *connection.Client) error {
	l.disconnected <- struct{}{}
	return nil
}

func fixture(t *testing.T) (Config, *master.Master, *lifecycle) {
	t.Helper()
	m := master.New(master.Config{Logger: slog.New(slog.DiscardHandler)})
	t.Cleanup(func() {
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	hooks := &lifecycle{connected: make(chan string, 8), disconnected: make(chan struct{}, 8)}
	if err := m.Addons.Add(t.Context(), hooks); err != nil {
		t.Fatal(err)
	}
	registry := new(proxy.Connections)
	t.Cleanup(registry.Close)
	handler, err := proxy.NewHandler(proxy.Config{Manager: m.Addons, Options: m.Options, Connections: registry, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return Config{Handler: handler, Logger: slog.New(slog.DiscardHandler)}, m, hooks
}

func makeInstance(t *testing.T, spec string, cfg Config) *Instance {
	t.Helper()
	mode, err := modespec.Parse(spec)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := New(mode, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Stop() })
	return instance
}

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(30 * time.Second):
		buf := make([]byte, 1<<20)
		t.Fatalf("timed out waiting for lifecycle signal\n%s", buf[:runtime.Stack(buf, true)])
		var zero T
		return zero
	}
}

var _ addon.ClientConnectedHandler = (*lifecycle)(nil)
