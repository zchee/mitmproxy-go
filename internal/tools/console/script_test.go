// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
	"github.com/zchee/mitmproxy-go/script"
)

func TestScriptAssembly(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"registered": {run: scriptAssemblyRegistered},
			"close_join": {run: scriptAssemblyCloseJoin},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}

func scriptAssemblyMaster(t *testing.T) *Master {
	t.Helper()
	opts := options.New()
	if err := opts.Update(t.Context(), map[string]any{"confdir": t.TempDir(), "server": false}); err != nil {
		t.Fatal(err)
	}
	m, err := New(t.Context(), Config{Options: opts, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	return m
}

func scriptAssemblySource(t *testing.T, source string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "addon.star")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func scriptAssemblyRegistered(t *testing.T) {
	m := scriptAssemblyMaster(t)
	if _, ok := m.Addons.Get("scriptloader").(*script.Loader); !ok {
		t.Fatal("default addon set lacks the real script loader")
	}
	var neighbors []string
	chain := m.Addons.Chain()
	for i, a := range chain {
		if a == m.scripts && i > 0 && i+1 < len(chain) {
			neighbors = []string{fmt.Sprintf("%T", chain[i-1]), fmt.Sprintf("%T", a), fmt.Sprintf("%T", chain[i+1])}
		}
	}
	if diff := gocmp.Diff([]string{"*proxyserver.ProxyServer", "*script.Loader", "*dnsresolver.DnsResolver"}, neighbors); diff != "" {
		t.Fatalf("default addon ordering (-want +got):\n%s", diff)
	}
	if !m.Options.Has("scripts") || !m.Options.Has("script_max_steps") {
		t.Fatal("scripting options were not registered before command-line construction")
	}
	path := scriptAssemblySource(t, "def on_load(loader):\n    loader.add_option(\"assembly_option\", \"str\", \"loaded\", \"Assembly option.\")\ndef running():\n    ctx.options.assembly_option = \"ran\"\n")
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		return m.Options.Update(ctx, map[string]any{"scripts": []string{path}})
	}); err != nil {
		t.Fatal(err)
	}
	if got := m.Options.Str("assembly_option"); got != "loaded" {
		t.Fatalf("initial script load did not finish synchronously: %q", got)
	}
	runPath := scriptAssemblySource(t, "def running():\n    ctx.options.assembly_option = \"script.run\"\n")
	if _, err := m.Call(t.Context(), "script.run", []flow.Flow{}, command.Path(runPath)); err != nil {
		t.Fatal(err)
	}
	if got := m.Options.Str("assembly_option"); got != "script.run" {
		t.Fatalf("registered script.run did not invoke its temporary module: %q", got)
	}
}

func scriptAssemblyCloseJoin(t *testing.T) {
	for _, mode := range []string{"metadata", "running", "startup_failure", "unselected_presentation"} {
		m := scriptAssemblyMaster(t)
		if mode == "running" || mode == "startup_failure" {
			if _, err := m.NewModel(); err != nil {
				t.Fatal(err)
			}
		}
		started, stopped := make(chan struct{}), make(chan struct{})
		origin := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			close(started)
			<-r.Context().Done()
			close(stopped)
		}))
		t.Cleanup(origin.Close)
		path := scriptAssemblySource(t, fmt.Sprintf("def _request(f):\n    ctx.http_get(%q)\nrequest = concurrent(_request)\ndef running():\n    ctx.master.shutdown()\n", origin.URL))
		if err := m.Do(t.Context(), func(ctx context.Context) error {
			return m.Options.Update(ctx, map[string]any{"scripts": []string{path}})
		}); err != nil {
			t.Fatalf("%s: load: %v", mode, err)
		}
		joined := make(chan error, 1)
		go func() { joined <- m.Addons.Trigger(t.Context(), addon.RequestHook{Flow: testflow.TFlow()}) }()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: script HTTP request never reached the real local origin", mode)
		}
		if mode == "metadata" {
			if err := m.Close(t.Context()); err != nil {
				t.Fatalf("metadata Close: %v", err)
			}
		} else {
			if mode == "startup_failure" {
				m.Logger().Error("script assembly startup failure")
			}
			err := m.Run(t.Context())
			if (err != nil) != (mode != "running") {
				t.Fatalf("%s: Run returned %v", mode, err)
			}
		}
		select {
		case err := <-joined:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("%s: request hook error = %v, want context.Canceled", mode, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: script worker did not join outside dispatch", mode)
		}
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: script transport was not canceled", mode)
		}
		if err := m.Close(t.Context()); err != nil {
			t.Fatalf("%s: repeated Close: %v", mode, err)
		}
		origin.Close()
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if m, err := New(ctx, Config{Stdout: io.Discard, Stderr: io.Discard}); err == nil || m != nil {
		t.Fatalf("construction cancellation returned master=%v, err=%v", m, err)
	}
}
