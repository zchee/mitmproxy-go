// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/platform"
	"github.com/zchee/mitmproxy-go/options"
)

type transparentLog struct {
	slog.Handler
	errors chan string
}

// Enabled includes lookup diagnostics in the bounded test recorder.
func (*transparentLog) Enabled(context.Context, slog.Level) bool { return true }

// Handle records immutable failure text without retaining mutable hook state.
func (l *transparentLog) Handle(_ context.Context, record slog.Record) error {
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == "error" {
			l.errors <- attr.Value.String()
		}
		return true
	})
	return nil
}

func TestTransparentModeLifecycle(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	tests := map[string]struct{ cancel bool }{
		"Stop does not join an accepted client under dispatch": {},
		"Start context cancellation closes accepted clients":   {cancel: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, m, hooks := fixture(t)
			limiter := new(ClientLimiter)
			limiter.SetLimit(1)
			cfg.ClientLimiter = limiter
			logs := &transparentLog{Handler: slog.DiscardHandler, errors: make(chan string, 8)}
			cfg.Logger = slog.New(logs)
			if err := m.Options.Add(t.Context(), "connection_strategy", options.TypeStr, "lazy", "Origin connection strategy."); err != nil {
				t.Fatal(err)
			}
			instance := makeInstance(t, "transparent@127.0.0.1:0", cfg)
			instance.checkTransparent = func(ctx context.Context) error { return ctx.Err() }
			lookupFailure := errors.New("original destination lookup denied")
			var calls atomic.Int32
			instance.originalAddr = func(ctx context.Context, raw *net.TCPConn) (connection.Address, error) {
				if err := m.Do(ctx, func(context.Context) error { return nil }); err != nil {
					return connection.Address{}, err
				}
				if raw.LocalAddr() == nil || raw.RemoteAddr() == nil {
					t.Error("lookup did not receive the accepted raw TCP socket")
				}
				if calls.Add(1) == 1 {
					return connection.Address{}, lookupFailure
				}
				return connection.Address{Host: "192.0.2.42", Port: 443}, nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if err := instance.Start(ctx); err != nil {
				t.Fatal(err)
			}
			address := instance.ListenAddrs()[0].String()
			failed, err := new(net.Dialer).DialContext(t.Context(), "tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = failed.Close() })
			if err := failed.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var one [1]byte
			if n, err := failed.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("lookup failure client read = %d, %v", n, err)
			}
			if got := await(t, logs.errors); !strings.Contains(got, lookupFailure.Error()) {
				t.Fatalf("lookup diagnostic lost original cause: %q", got)
			}
			waitTransparentClients(t, limiter, 0)
			if len(hooks.connected) != 0 || !instance.IsRunning() {
				t.Fatal("failed lookup reached Handler or stopped the listener")
			}
			client, err := new(net.Dialer).DialContext(t.Context(), "tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			await(t, hooks.connected)
			if calls.Load() != 2 || limiter.active.Load() != 1 {
				t.Fatalf("lookup calls = %d, active slots = %d", calls.Load(), limiter.active.Load())
			}
			if tt.cancel {
				cancel()
			} else {
				if err := m.Do(t.Context(), func(context.Context) error { return instance.Stop() }); err != nil {
					t.Fatal(err)
				}
				if instance.IsRunning() || len(instance.ListenAddrs()) != 0 || limiter.active.Load() != 1 {
					t.Fatal("Stop retained the listener or joined the accepted client")
				}
				_ = client.Close()
			}
			await(t, hooks.disconnected)
			waitTransparentClients(t, limiter, 0)
		})
	}
	t.Run("availability failure precedes bind", func(t *testing.T) {
		cfg, _, _ := fixture(t)
		instance := makeInstance(t, "transparent@127.0.0.1:0", cfg)
		instance.checkTransparent = func(context.Context) error { return platform.ErrUnsupported }
		instance.listenTCP = func(context.Context, string, string) (net.Listener, error) {
			t.Fatal("availability refusal opened a listener")
			return nil, platform.ErrUnsupported
		}
		if err := instance.Start(t.Context()); !errors.Is(err, platform.ErrUnsupported) || !errors.Is(instance.LastError(), platform.ErrUnsupported) || instance.IsRunning() {
			t.Fatalf("availability failure state: error=%v last=%v running=%v", err, instance.LastError(), instance.IsRunning())
		}
	})
	t.Run("canceled lookup releases the client", func(t *testing.T) {
		cfg, _, hooks := fixture(t)
		limiter := new(ClientLimiter)
		cfg.ClientLimiter = limiter
		instance := makeInstance(t, "transparent@127.0.0.1:0", cfg)
		instance.checkTransparent = func(ctx context.Context) error { return ctx.Err() }
		entered := make(chan struct{})
		instance.originalAddr = func(ctx context.Context, _ *net.TCPConn) (connection.Address, error) {
			close(entered)
			<-ctx.Done()
			return connection.Address{}, ctx.Err()
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		if err := instance.Start(ctx); err != nil {
			t.Fatal(err)
		}
		client, err := new(net.Dialer).DialContext(t.Context(), "tcp", instance.ListenAddrs()[0].String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		await(t, entered)
		cancel()
		if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatal(err)
		}
		var one [1]byte
		if n, err := client.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("canceled lookup client read = %d, %v", n, err)
		}
		waitTransparentClients(t, limiter, 0)
		if len(hooks.connected) != 0 {
			t.Fatal("canceled lookup reached Handler")
		}
	})
	t.Run("immutable endpoint preserves addresses and half-close", func(t *testing.T) {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		raw, err := listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = raw.Close() })
		wrapped := &transparentConn{TCPConn: raw, endpoint: "192.0.2.42:443"}
		if wrapped.LocalAddr().String() != raw.LocalAddr().String() || wrapped.RemoteAddr().String() != raw.RemoteAddr().String() {
			t.Fatal("captured metadata replaced actual socket addresses")
		}
		if value, ok := wrapped.GetExtraInfo("remote_endpoint"); !ok || value != "192.0.2.42:443" {
			t.Fatalf("captured endpoint = %v, %v", value, ok)
		}
		if value, ok := wrapped.GetExtraInfo("unknown"); ok || value != nil {
			t.Fatal("unknown metadata key was published")
		}
		if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := wrapped.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := wrapped.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		var one [1]byte
		if n, err := client.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("half-close client read = %d, %v", n, err)
		}
		if _, err := client.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(wrapped, one[:]); err != nil {
			t.Fatal(err)
		}
		if diff := gocmp.Diff([]byte("x"), one[:]); diff != "" {
			t.Fatal(diff)
		}
	})
}

func waitTransparentClients(t *testing.T, limiter *ClientLimiter, want int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for limiter.active.Load() != want {
		if err := ctx.Err(); err != nil {
			t.Fatalf("active clients = %d, want %d: %v", limiter.active.Load(), want, err)
		}
		runtime.Gosched()
	}
}
