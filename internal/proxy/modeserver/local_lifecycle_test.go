// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/internal/local"
)

func TestLocalIPCStartupFailureReleasesFrontend(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}
	tests := map[string]struct{}{"missing native executable releases reservation": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			broken := local.NewMacOSRedirector(t.TempDir(), filepath.Join(t.TempDir(), "absent"))
			t.Cleanup(func() { _ = broken.Close() })
			instance := localIPCMode(t, cfg, broken, "local")
			if err := instance.Start(t.Context()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("startup = %v", err)
			}
			if instance.IsRunning() || instance.LastError() == nil {
				t.Fatal("failed startup retained frontend")
			}
			redirector, control := localIPCFixture(t)
			next := localIPCMode(t, cfg, redirector, "local")
			t.Cleanup(func() { _ = next.Stop() })
			if err := next.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			localIPCRead(t, control, new(local.InterceptConf))
			if err := next.Stop(); err != nil {
				t.Fatal(err)
			}
			localIPCRead(t, control, new(local.InterceptConf))
		})
	}
}

func TestLocalIPCLiveFailureAndCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}
	tests := map[string]struct{ cancel bool }{"native control EOF retains cleanup cause": {}, "process cancellation joins frontend": {cancel: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			redirector, control := localIPCFixture(t)
			cfg, _, _ := fixture(t)
			instance := localIPCMode(t, cfg, redirector, "local")
			t.Cleanup(func() { _ = instance.Stop() })
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if err := instance.Start(ctx); err != nil {
				t.Fatal(err)
			}
			localIPCRead(t, control, new(local.InterceptConf))
			if tt.cancel {
				cancel()
			} else {
				if err := control.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if tt.cancel {
				if err := redirector.Launch(t.Context()); err != nil {
					t.Fatalf("frontend cancellation ended process daemon: %v", err)
				}
			} else {
				waitCtx, waitCancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer waitCancel()
				conn, _, err := redirector.(local.StreamRedirector).AcceptTCP(waitCtx)
				if conn != nil {
					_ = conn.Close()
					t.Fatal("unexpected native connection")
				}
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("control EOF = %v", err)
				}
			}
			stopErr := instance.Stop()
			if tt.cancel {
				if stopErr != nil {
					t.Fatal(stopErr)
				}
				localIPCRead(t, control, new(local.InterceptConf))
			} else if !errors.Is(errors.Join(stopErr, instance.LastError()), net.ErrClosed) {
				t.Fatalf("cleanup cause lost: Stop=%v LastError=%v", stopErr, instance.LastError())
			}
			if instance.IsRunning() || len(instance.ListenAddrs()) != 0 {
				t.Fatal("failed frontend remained active")
			}
		})
	}
}
