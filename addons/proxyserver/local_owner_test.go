// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxyserver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/zchee/mitmproxy-go/internal/local"
)

func TestLocalAddonLiveOwnerShutdown(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}
	tests := map[string]struct{}{"disable active frontend before final process close": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			m, ps, _, _ := fixture(t, false)
			root := t.TempDir()
			fifo := filepath.Join(root, "ready")
			if output, err := exec.CommandContext(t.Context(), "mkfifo", fifo).CombinedOutput(); err != nil {
				t.Fatalf("mkfifo: %v %s", err, output)
			}
			ready, err := os.OpenFile(fifo, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ready.Close() })
			starter := filepath.Join(root, "starter")
			if err := os.WriteFile(starter, []byte("#!/bin/sh\nprintf x > "+strconv.Quote(fifo)+"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			daemon := local.NewMacOSRedirector(root, starter)
			ps.localDaemon.redirector = daemon
			t.Cleanup(func() { _ = daemon.Close() })
			launch := make(chan error, 1)
			go func() { launch <- daemon.Launch(ps.lifetime) }()
			signal := make(chan error, 1)
			go func() { var b [1]byte; _, err := io.ReadFull(ready, b[:]); signal <- err }()
			select {
			case err := <-signal:
				if err != nil {
					t.Fatal(err)
				}
			case err := <-launch:
				t.Fatalf("native launch before ready: %v", err)
			case <-time.After(30 * time.Second):
				t.Fatal("native owner readiness hang detector")
			}
			control, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: "/tmp/mitmproxy-" + strconv.Itoa(os.Getpid()), Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = control.Close() })
			if err := <-launch; err != nil {
				t.Fatal(err)
			}
			if err := control.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			readRules := func() []string {
				var prefix [4]byte
				if _, err := io.ReadFull(control, prefix[:]); err != nil {
					t.Fatal(err)
				}
				length := binary.BigEndian.Uint32(prefix[:])
				if length > 8<<20 {
					t.Fatal("invalid IPC message length")
				}
				payload := make([]byte, length)
				if _, err := io.ReadFull(control, payload); err != nil {
					t.Fatal(err)
				}
				var conf local.InterceptConf
				if err := proto.Unmarshal(payload, &conf); err != nil {
					t.Fatal(err)
				}
				return conf.Actions
			}
			update(t, m, map[string]any{"mode": []string{"local:curl"}, "server": true})
			if err := ps.SetupServers(t.Context()); err != nil {
				t.Fatal(err)
			}
			if rules := readRules(); len(rules) != 2 || rules[0] != "curl" {
				t.Fatalf("active rules=%v", rules)
			}
			state := ps.instances.Load()
			if len(state.instances) != 1 {
				t.Fatal("local frontend missing")
			}
			if err := state.instances[0].Stop(); err != nil {
				t.Fatal(err)
			}
			if rules := readRules(); len(rules) != 0 {
				t.Fatalf("disabled rules=%v", rules)
			}
			if err := daemon.Launch(ps.lifetime); err != nil {
				t.Fatalf("frontend stopped daemon: %v", err)
			}
			if err := m.Do(t.Context(), ps.Done); err != nil {
				t.Fatal(err)
			}
			ps.workers.Wait()
			if err := daemon.Launch(t.Context()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("final close did not join daemon: %v", err)
			}
		})
	}
}

func TestLocalConfigureNoPort(t *testing.T) {
	tests := map[string]struct{ modes []string }{
		"local frontends ignore fallback listen port": {modes: []string{"local", "local:curl"}},
		"TUN frontends ignore fallback listen port":   {modes: []string{"tun", "tun:utun3"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, ps, _, _ := fixture(t, false)
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				return m.Options.Update(ctx, map[string]any{"server": false, "mode": tt.modes, "listen_port": new(-1)})
			}); err != nil {
				t.Fatal(err)
			}
			if len(ps.ListenAddrs()) != 0 {
				t.Fatal("configuration opened native listener")
			}
		})
	}
}

func TestLocalAddonLazyOwnerFinalClose(t *testing.T) {
	tests := map[string]struct{}{"one inert process daemon shared until final shutdown": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			m, ps, _, _ := fixture(t, false)
			if ps.localDaemon.redirector != nil {
				t.Fatal("regular configuration allocated local daemon")
			}
			update(t, m, map[string]any{"server": false, "mode": []string{"local", "local:curl"}, "confdir": t.TempDir()})
			first := ps.localDaemon.redirector
			if first == nil {
				t.Fatal("local configuration did not construct owner")
			}
			update(t, m, map[string]any{"mode": []string{"regular"}})
			update(t, m, map[string]any{"mode": []string{"local:wget"}, "confdir": t.TempDir()})
			if ps.localDaemon.redirector != first {
				t.Fatal("reconfiguration replaced process daemon")
			}
			if err := ps.SetupServers(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := m.Do(t.Context(), ps.Done); err != nil {
				t.Fatal(err)
			}
			ps.workers.Wait()
			if err := first.Launch(t.Context()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("final owner not closed: %v", err)
			}
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			if !ps.localDaemon.closed {
				t.Fatal("final owner allowed construction after shutdown")
			}
		})
	}
}
