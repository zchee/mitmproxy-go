// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/zchee/mitmproxy-go/internal/local"
	"github.com/zchee/mitmproxy-go/internal/wireguard"
)

func TestWebStatePublication(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"transitions/wireguard_monitor":     {run: testWebWireGuardPublication},
		"transitions/tun_monitor":           {run: testWebTunPublication},
		"transitions/local_monitor":         {run: testWebLocalPublication},
		"transitions/instance_cancellation": {run: testWebCancellationPublication},
	}
	for name, tt := range tests {
		t.Run(name, tt.run)
	}
}

func awaitWebPublication(t *testing.T, changed <-chan struct{}) {
	t.Helper()
	select {
	case <-changed:
	case <-time.After(30 * time.Second):
		t.Fatal("completed state publication did not signal refresh")
	}
}

func assertWebStopped(t *testing.T, instance *Instance, field string, failure bool) {
	t.Helper()
	got := instance.WebState()
	if revision := instance.presentationRevision.Load(); revision < 2 {
		t.Fatalf("completed lifecycle did not advance invalidation revision: %d", revision)
	}
	if got["is_running"] != false || (got["last_exception"] != nil) != failure {
		t.Fatal("stopped presentation has an unexpected running or error state")
	}
	if diff := cmp.Diff([][2]any{}, got["listen_addrs"]); diff != "" {
		t.Fatalf("stopped addresses (-want +got):\n%s", diff)
	}
	if field != "" && got[field] != nil {
		t.Fatal("stopped native presentation retained source metadata")
	}
}

func testWebWireGuardPublication(t *testing.T) {
	for _, unexpected := range []bool{true, false} {
		cfg, _, _ := fixture(t)
		changed := make(chan struct{}, 1)
		cfg.PresentationChanged = changed
		cfg.PresentationRevision = new(atomic.Uint64)
		path := filepath.Join(t.TempDir(), "wireguard.conf")
		instance := makeInstance(t, "wireguard:"+path+"@127.0.0.1:0", cfg)
		t.Cleanup(func() { _ = instance.Stop() })
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		if err := instance.Start(ctx); err != nil {
			t.Fatal(err)
		}
		awaitWebPublication(t, changed)
		live := instance.WebState()
		config, ok := live["wireguard_conf"].(string)
		if !ok || !strings.Contains(config, "[Interface]") || live["is_running"] != true {
			t.Fatal("WireGuard success presentation lacks client configuration or running state")
		}
		configuration, err := wireguard.LoadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		clientKeys, err := configuration.PeerKeys()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(config+"\n", "PrivateKey = "+clientKeys[0]+"\n") {
			t.Fatal("WireGuard presentation does not contain the first client private-key line")
		}
		if strings.Contains(config, configuration.ServerKey) {
			t.Fatal("WireGuard presentation exposes the server private key")
		}
		source := instance.state.Load().wireguard
		if unexpected {
			if err := source.server.Close(); err != nil {
				t.Fatal(err)
			}
		} else {
			cancel()
		}
		awaitWebPublication(t, changed)
		select {
		case <-source.monitorDone:
		case <-time.After(30 * time.Second):
			t.Fatal("WireGuard monitor did not join")
		}
		assertWebStopped(t, instance, "wireguard_conf", unexpected)
		if live["is_running"] != true || live["wireguard_conf"] != config {
			t.Fatal("retained WireGuard metadata changed")
		}
		if err := instance.Stop(); err != nil {
			t.Fatal(err)
		}
	}
}

// A device boundary controls completion without opening a privileged interface.
// The existing channel TUN supplies the rest of the real bridge/device contract.
type webFailureTun struct {
	wgtun.Device
	fail   chan struct{}
	closed chan struct{}
	once   sync.Once
}

func (d *webFailureTun) Read(_ [][]byte, _ []int, _ int) (int, error) {
	select {
	case <-d.fail:
		return 0, io.ErrUnexpectedEOF
	case <-d.closed:
		return 0, io.EOF
	}
}

func (d *webFailureTun) Close() error {
	var err error
	d.once.Do(func() { close(d.closed); err = d.Device.Close() })
	return err
}

func testWebTunPublication(t *testing.T) {
	for _, unexpected := range []bool{true, false} {
		cfg, _, _ := fixture(t)
		changed := make(chan struct{}, 1)
		cfg.PresentationChanged = changed
		cfg.PresentationRevision = new(atomic.Uint64)
		instance := makeInstance(t, "tun", cfg)
		device := &webFailureTun{Device: tuntest.NewChannelTUN().TUN(), fail: make(chan struct{}), closed: make(chan struct{})}
		instance.openTun = func(string, *slog.Logger) (wgtun.Device, error) { return device, nil }
		t.Cleanup(func() { _ = instance.Stop() })
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		if err := instance.Start(ctx); err != nil {
			t.Fatal(err)
		}
		awaitWebPublication(t, changed)
		live := instance.WebState()
		name, ok := live["tun_name"].(string)
		if !ok || name == "" || live["is_running"] != true {
			t.Fatal("TUN success presentation lacks interface name or running state")
		}
		source := instance.state.Load().tun
		if unexpected {
			close(device.fail)
		} else {
			cancel()
		}
		awaitWebPublication(t, changed)
		select {
		case <-source.monitorDone:
		case <-time.After(30 * time.Second):
			t.Fatal("TUN monitor did not join")
		}
		assertWebStopped(t, instance, "tun_name", unexpected)
		if unexpected && !errors.Is(instance.LastError(), io.ErrUnexpectedEOF) {
			t.Fatalf("lost device failure: %v", instance.LastError())
		}
		if live["tun_name"] != name || live["is_running"] != true {
			t.Fatal("retained TUN metadata changed")
		}
		if err := instance.Stop(); err != nil {
			t.Fatal(err)
		}
	}
}

func testWebLocalPublication(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}
	for _, unexpected := range []bool{true, false} {
		redirector, control := localIPCFixture(t)
		cfg, _, _ := fixture(t)
		changed := make(chan struct{}, 1)
		cfg.PresentationChanged = changed
		cfg.PresentationRevision = new(atomic.Uint64)
		cfg.LocalRedirector = redirector
		instance := makeInstance(t, "local", cfg)
		t.Cleanup(func() { _ = instance.Stop() })
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		if err := instance.Start(ctx); err != nil {
			t.Fatal(err)
		}
		localIPCRead(t, control, new(local.InterceptConf))
		awaitWebPublication(t, changed)
		live := instance.WebState()
		if live["is_running"] != true || currentLocal.Load() != instance {
			t.Fatal("local success presentation or active instance was not published")
		}
		source := instance.state.Load().local
		if unexpected {
			if err := control.Close(); err != nil {
				t.Fatal(err)
			}
		} else {
			cancel()
		}
		awaitWebPublication(t, changed)
		if currentLocal.Load() != nil {
			t.Fatal("refresh preceded currentLocal clearing")
		}
		select {
		case <-source.monitorDone:
		case <-time.After(30 * time.Second):
			t.Fatal("local monitor did not join")
		}
		assertWebStopped(t, instance, "", unexpected)
		if !unexpected {
			localIPCRead(t, control, new(local.InterceptConf))
		}
		if live["is_running"] != true {
			t.Fatal("retained local state changed")
		}
		if err := instance.Stop(); err != nil {
			t.Fatal(err)
		}
		assertWebStopped(t, instance, "", unexpected)
		if err := redirector.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func testWebCancellationPublication(t *testing.T) {
	cfg, _, _ := fixture(t)
	changed := make(chan struct{}, 1)
	cfg.PresentationChanged = changed
	cfg.PresentationRevision = new(atomic.Uint64)
	instance := makeInstance(t, "regular@127.0.0.1:0", cfg)
	t.Cleanup(func() { _ = instance.Stop() })
	for range 2 {
		ctx, cancel := context.WithCancel(t.Context())
		if err := instance.Start(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		awaitWebPublication(t, changed)
		live := instance.WebState()
		if live["is_running"] != true {
			cancel()
			t.Fatal("listener did not publish success")
		}
		cancel()
		awaitWebPublication(t, changed)
		assertWebStopped(t, instance, "", false)
		if live["is_running"] != true {
			t.Fatal("retained instance state changed after cancellation")
		}
	}
}
