// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestMacOSConstructor(t *testing.T) {
	r := NewMacOSRedirector("cache", "override").(*macOSRedirector)
	if r.confdir != "cache" || r.overridePath != "override" {
		t.Fatal("constructor discarded artifact selection")
	}
	if want := "/tmp/mitmproxy-" + strconv.Itoa(os.Getpid()); r.socketPath != want {
		t.Fatalf("socket path = %q, want %q", r.socketPath, want)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Launch(t.Context()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Launch after Close = %v", err)
	}
}

func syntheticMacOSStarter(t *testing.T, root string, app bool) string {
	t.Helper()
	path := filepath.Join(root, "starter")
	if app {
		path = filepath.Join(root, "Synthetic.app", "Contents", "MacOS", "Mitmproxy Redirector")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// This starter exits without installing or activating any native extension.
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if app {
		return filepath.Join(root, "Synthetic.app")
	}
	return path
}

func syntheticMacOSPeer(t *testing.T, r *macOSRedirector, ctx context.Context) *net.UnixConn {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- r.Launch(ctx) }()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: r.socketPath, Net: "unix"})
		if err == nil {
			select {
			case err := <-result:
				if err != nil {
					_ = peer.Close()
					t.Fatal(err)
				}
			case <-ctx.Done():
				_ = peer.Close()
				t.Fatal(ctx.Err())
			}
			if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = peer.Close() })
			return peer
		}
		select {
		case err := <-result:
			t.Fatalf("starter failed before control connection: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
}

// Synthetic starters and Unix peers cover the lifecycle contract, not native
// macOS system-extension installation or runtime acceptance.
func TestMacOSLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("synthetic starter uses a Unix shell and Unix sockets")
	}
	root := t.TempDir()
	tests := map[string]struct {
		app bool
		run func(*testing.T, *macOSRedirector, *net.UnixConn)
	}{
		"success: normalized rules and frontend stop": {run: func(t *testing.T, r *macOSRedirector, peer *net.UnixConn) {
			for _, spec := range []string{"curl, !123", ""} {
				ctx, cancel := context.WithCancel(t.Context())
				if err := r.SetIntercept(ctx, spec); err != nil {
					cancel()
					t.Fatal(err)
				}
				cancel()
				var got InterceptConf
				if err := readIPC(peer, &got); err != nil {
					t.Fatal(err)
				}
				want, err := EncodeInterceptSpec(spec, uint32(os.Getpid()))
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(want.GetActions(), got.GetActions()); diff != "" {
					t.Fatalf("control rules (-want +got):\n%s", diff)
				}
			}
			if err := r.Launch(t.Context()); err != nil {
				t.Fatalf("frontend cancellation stopped daemon: %v", err)
			}
		}},
		"success: app directory starter": {app: true, run: func(t *testing.T, r *macOSRedirector, _ *net.UnixConn) {
			if err := r.Launch(t.Context()); err != nil {
				t.Fatal(err)
			}
		}},
		"success: concurrent launch is idempotent": {run: func(t *testing.T, r *macOSRedirector, _ *net.UnixConn) {
			var group sync.WaitGroup
			for range 8 {
				group.Go(func() {
					if err := r.Launch(t.Context()); err != nil {
						t.Error(err)
					}
				})
			}
			group.Wait()
		}},
		"success: concurrent final close": {run: func(t *testing.T, r *macOSRedirector, _ *net.UnixConn) {
			var group sync.WaitGroup
			for range 8 {
				group.Go(func() {
					if err := r.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			group.Wait()
			if _, err := os.Lstat(r.socketPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("control socket survived Close: %v", err)
			}
			if err := r.SetIntercept(t.Context(), "curl"); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("SetIntercept after Close = %v", err)
			}
		}},
		"error: invalid rule does not poison control": {run: func(t *testing.T, r *macOSRedirector, peer *net.UnixConn) {
			if err := r.SetIntercept(t.Context(), "!"); err == nil {
				t.Fatal("invalid rule accepted")
			}
			if err := r.SetIntercept(t.Context(), "curl"); err != nil {
				t.Fatal(err)
			}
			if err := readIPC(peer, new(InterceptConf)); err != nil {
				t.Fatal(err)
			}
		}},
		"error: queued write honors cancellation": {run: func(t *testing.T, r *macOSRedirector, _ *net.UnixConn) {
			r.writeGate <- struct{}{}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := r.SetIntercept(ctx, "curl"); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled queued write = %v", err)
			}
			<-r.writeGate
		}},
		"error: blocked control write cancels": {run: func(t *testing.T, r *macOSRedirector, _ *net.UnixConn) {
			if err := r.control.SetWriteBuffer(1); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			if err := r.SetIntercept(ctx, strings.Repeat("x", maxIPCMessageSize-128)); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("blocked write error = %v", err)
			}
		}},
		"error: control EOF stops daemon": {run: func(t *testing.T, r *macOSRedirector, peer *net.UnixConn) {
			if err := peer.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-r.closedCh:
			case <-t.Context().Done():
				t.Fatal(t.Context().Err())
			}
			if err := r.SetIntercept(t.Context(), "curl"); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after control EOF = %v", err)
			}
		}},
	}
	index := 0
	for name, test := range tests {
		index++
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, strconv.Itoa(index))
			r := NewMacOSRedirector(dir, syntheticMacOSStarter(t, dir, test.app)).(*macOSRedirector)
			r.socketPath = filepath.Join(dir, "s")
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
			peer := syntheticMacOSPeer(t, r, ctx)
			test.run(t, r, peer)
		})
	}
}

func TestMacOSLaunchErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("synthetic starter uses a Unix shell and Unix sockets")
	}
	root := t.TempDir()
	tests := map[string]struct {
		missing bool
		cancel  bool
		close   bool
		escape  bool
	}{
		"error: missing override":       {missing: true},
		"error: app executable escape":  {escape: true},
		"error: canceled launch":        {cancel: true},
		"error: control accept timeout": {},
		"error: close wakes launch":     {close: true},
	}
	index := 0
	for name, test := range tests {
		index++
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, strconv.Itoa(index))
			path := syntheticMacOSStarter(t, dir, false)
			if test.missing {
				path += ".missing"
			}
			if test.escape {
				outside := syntheticMacOSStarter(t, filepath.Join(dir, "outside"), true)
				path = filepath.Join(dir, "Escape.app")
				if err := os.MkdirAll(filepath.Join(path, "Contents"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(outside, "Contents", "MacOS"), filepath.Join(path, "Contents", "MacOS")); err != nil {
					t.Fatal(err)
				}
			}
			r := NewMacOSRedirector(dir, path).(*macOSRedirector)
			r.socketPath = filepath.Join(dir, "s")
			r.connectTimeout = 20 * time.Millisecond
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.cancel {
				cancel()
			}
			if test.close {
				result := make(chan error, 1)
				go func() { result <- r.Launch(ctx) }()
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				if err := <-result; !errors.Is(err, net.ErrClosed) {
					t.Fatalf("closed launch = %v", err)
				}
			} else {
				err := r.Launch(ctx)
				if err == nil {
					t.Fatal("launch without control peer succeeded")
				}
				if test.escape && !strings.Contains(err.Error(), "escapes app directory") {
					t.Fatalf("app escape error = %v", err)
				}
				if test.cancel && !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled launch error = %v", err)
				}
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMacOSLifetime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("synthetic starter uses a Unix shell and Unix sockets")
	}
	root := t.TempDir()
	r := NewMacOSRedirector(root, syntheticMacOSStarter(t, root, false)).(*macOSRedirector)
	r.socketPath = filepath.Join(root, "s")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_ = syntheticMacOSPeer(t, r, ctx)
	cancel()
	select {
	case <-r.closedCh:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadPacket(t.Context()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("packet read after process cancellation = %v", err)
	}
}

func TestMacOSPacketUnsupported(t *testing.T) {
	r := NewMacOSRedirector("", "")
	tests := map[string]struct{ write bool }{
		"error: packet read unsupported":  {},
		"error: packet write unsupported": {write: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var err error
			if test.write {
				err = r.WritePacket(t.Context(), new(Packet))
			} else {
				_, err = r.ReadPacket(t.Context())
			}
			if !errors.Is(err, errMacOSPacketUnsupported) {
				t.Fatalf("packet operation = %v", err)
			}
		})
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}
