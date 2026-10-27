// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package debugserver

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/internal/telemetry"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

type serverFixture struct {
	c      *Controller
	m      *master.Master
	client *http.Client
}

func debugController(t *testing.T, running bool, cfg Config) *serverFixture {
	t.Helper()
	c := New(cfg)
	m := master.New(master.Config{})
	c.Bind(m)
	if err := m.Addons.Add(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	if running {
		if err := m.Addons.Trigger(t.Context(), addon.RunningHook{}); err != nil {
			t.Fatal(err)
		}
	}
	transport := &http.Transport{Proxy: nil}
	x := &serverFixture{c: c, m: m, client: &http.Client{Transport: transport, Timeout: 3 * time.Second}}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 6*time.Second)
		defer cancel()
		if err := c.Close(ctx); err != nil {
			t.Error(err)
		}
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return x
}

func setDebugAddress(t *testing.T, x *serverFixture, value string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	if err := x.m.Do(ctx, func(ctx context.Context) error {
		return x.m.Options.Update(ctx, map[string]any{addressOption: value})
	}); err != nil {
		return err
	}
	return x.c.Sync(ctx)
}

func currentServer(c *Controller) *serverGeneration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current
}

func getDebug(t *testing.T, x *serverFixture, path string) ([]byte, int) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+x.c.Status().Address+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := x.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		t.Fatal(err)
	}
	return data, response.StatusCode
}

func assertServerJoined(t *testing.T, g *serverGeneration) {
	t.Helper()
	if g == nil {
		t.Fatal("expected an owned server generation")
	}
	select {
	case <-g.joined:
	default:
		t.Fatal("listener/connection/handler work was not joined")
	}
	connection, err := new(net.Dialer).DialContext(t.Context(), "tcp", g.address)
	if err == nil {
		_ = connection.Close()
		t.Fatal("joined listener is still reachable")
	}
}

type rejectingAddress struct {
	opts  *options.Manager
	value string
}

func (r *rejectingAddress) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, ok := updated[addressOption]; ok && r.opts.Str(addressOption) == r.value {
		return &options.OptionsError{Msg: "owned option rejection"}
	}
	return nil
}

func TestDebugServer(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"disabled_unreachable": {run: func(t *testing.T) {
			x := debugController(t, true, Config{})
			if err := x.c.Sync(t.Context()); err != nil {
				t.Fatal(err)
			}
			if status := x.c.Status(); status.Enabled || status.Address != "" || currentServer(x.c) != nil {
				t.Fatalf("disabled controller owns a listener: %+v", status)
			}
			metadata, ok := x.m.Options.Lookup(addressOption)
			if !ok || metadata.Type() != options.TypeStr || metadata.Default() != "" || metadata.Current() != "" {
				t.Fatal("profiling control is not a disabled-by-default string option")
			}
			manifest, err := os.ReadFile("../../testdata/options-go-only.txt")
			if err != nil {
				t.Fatal(err)
			}
			want := strings.Join([]string{metadata.Name(), metadata.Type().String(), `""`, metadata.Help()}, "\t")
			matches := 0
			for line := range strings.SplitSeq(string(manifest), "\n") {
				if strings.HasPrefix(line, addressOption+"\t") {
					matches++
					if diff := gocmp.Diff(line, want); diff != "" {
						t.Fatalf("profiling option differs from manifest: %s", diff)
					}
				}
			}
			if matches != 1 {
				t.Fatalf("manifest has %d profiling option rows, want 1", matches)
			}
			if err := setDebugAddress(t, x, "0.0.0.0:6060"); err == nil {
				t.Fatal("wildcard configuration accepted")
			}
			if status := x.c.Status(); status.Enabled || status.Address != "" {
				t.Fatalf("refused address created a listener: %+v", status)
			}
		}},
		"pprof_private_mux": {run: func(t *testing.T) {
			x := debugController(t, true, Config{})
			if err := setDebugAddress(t, x, "localhost:0"); err != nil {
				t.Fatal(err)
			}
			g := currentServer(x.c)
			if g.server.Handler == http.DefaultServeMux || g.server.Handler == nil {
				t.Fatal("profiling server uses the global/default mux")
			}
			for _, path := range []string{"/debug/pprof/", "/debug/pprof/goroutine?debug=1", "/debug/pprof/heap", "/debug/pprof/symbol"} {
				body, code := getDebug(t, x, path)
				if code != http.StatusOK || len(body) == 0 {
					t.Fatalf("standard profiling handler %s: status=%d bytes=%d", path, code, len(body))
				}
			}
			if _, code := getDebug(t, x, "/options"); code != http.StatusNotFound {
				t.Fatalf("private mux exposed a frontend route: %d", code)
			}
			if g.server.ReadHeaderTimeout != 5*time.Second || g.server.MaxHeaderBytes != 16<<10 || g.server.IdleTimeout != 30*time.Second || g.server.WriteTimeout != 35*time.Second {
				t.Fatal("HTTP transport limits changed")
			}
		}},
		"debug_snapshot": {run: func(t *testing.T) {
			x := debugController(t, true, Config{Counters: func() telemetry.Status { return telemetry.Status{ActiveFlows: 7, HTTPFidelity: 1<<60 + 1} }})
			if err := setDebugAddress(t, x, "127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			body, code := getDebug(t, x, "/debug")
			var document struct {
				Runtime     []jsontext.Value `json:"runtime"`
				Telemetry   telemetry.Status `json:"telemetry"`
				Diagnostics Status           `json:"diagnostics"`
			}
			if code != http.StatusOK {
				t.Fatalf("diagnostics HTTP status=%d", code)
			}
			if err := json.Unmarshal(body, &document); err != nil {
				t.Fatal(err)
			}
			if len(document.Runtime) == 0 || document.Telemetry.ActiveFlows != 7 || document.Telemetry.HTTPFidelity != 1<<60+1 {
				t.Fatal("runtime metrics or exact instance counters are missing")
			}
			if diff := gocmp.Diff(x.c.Status(), document.Diagnostics); diff != "" {
				t.Fatal(diff)
			}
		}},
		"rebind": {run: func(t *testing.T) {
			x := debugController(t, true, Config{})
			if err := setDebugAddress(t, x, "127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			old := currentServer(x.c)
			if err := setDebugAddress(t, x, "localhost:0"); err != nil {
				t.Fatal(err)
			}
			assertServerJoined(t, old)
			if currentServer(x.c) == old || !x.c.Status().Enabled {
				t.Fatal("new generation was not published after the old join")
			}
			if _, code := getDebug(t, x, "/debug"); code != http.StatusOK {
				t.Fatal("rebound listener does not serve diagnostics")
			}
			current := currentServer(x.c)
			if err := setDebugAddress(t, x, "192.0.2.1:6060"); err == nil || currentServer(x.c) != current {
				t.Fatal("invalid update replaced the previous service")
			}
		}},
		"disable_ack": {run: func(t *testing.T) {
			x := debugController(t, true, Config{})
			if err := setDebugAddress(t, x, "127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			old := currentServer(x.c)
			getDebug(t, x, "/debug")
			if err := setDebugAddress(t, x, ""); err != nil {
				t.Fatal(err)
			}
			assertServerJoined(t, old)
			if status := x.c.Status(); status.Enabled || status.Address != "" || status.Requested != "" {
				t.Fatalf("disable was not acknowledged: %+v", status)
			}
		}},
		"bind_error": {run: func(t *testing.T) {
			listener, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := listener.Close(); err != nil {
					t.Error(err)
				}
			}()
			x := debugController(t, true, Config{})
			if err := setDebugAddress(t, x, listener.Addr().String()); err == nil {
				t.Fatal("bind failure was not surfaced by Sync")
			}
			if status := x.c.Status(); !status.Failed || status.Enabled || status.Address != "" || status.Requested != listener.Addr().String() {
				t.Fatalf("bind failure not distinguished from requested state: %+v", status)
			}
		}},
		"recover_after_bind_error": {run: func(t *testing.T) {
			listener, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := listener.Close(); err != nil {
					t.Error(err)
				}
			}()
			x := debugController(t, true, Config{})
			if err := setDebugAddress(t, x, listener.Addr().String()); err == nil {
				t.Fatal("occupied address unexpectedly bound")
			}
			if err := setDebugAddress(t, x, "127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			if status := x.c.Status(); !status.Enabled || status.Failed {
				t.Fatalf("recovery failed: %+v", status)
			}
			getDebug(t, x, "/debug")
		}},
		"rollback_stale": {run: func(t *testing.T) {
			x := debugController(t, true, Config{})
			if err := setDebugAddress(t, x, "127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			before := currentServer(x.c)
			if err := x.m.Addons.Add(t.Context(), &rejectingAddress{opts: x.m.Options, value: "localhost:0"}); err != nil {
				t.Fatal(err)
			}
			err := setDebugAddress(t, x, "localhost:0")
			if _, ok := errors.AsType[*options.OptionsError](err); !ok {
				t.Fatalf("rollback error=%v", err)
			}
			if err := x.c.Sync(t.Context()); err != nil {
				t.Fatal(err)
			}
			if currentServer(x.c) != before || x.c.Status().Requested != "127.0.0.1:0" {
				t.Fatal("rolled-back address replaced the current listener")
			}
			getDebug(t, x, "/debug")
		}},
		"partial_cleanup": {run: func(t *testing.T) {
			unbound := New(Config{})
			m := master.New(master.Config{})
			if err := m.Addons.Add(t.Context(), unbound); err == nil {
				t.Fatal("unbound addon accepted")
			}
			if err := unbound.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			x := debugController(t, false, Config{})
			if err := setDebugAddress(t, x, "127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			if currentServer(x.c) != nil || x.c.Status().Enabled {
				t.Fatal("metadata-only configuration opened a listener")
			}
			if err := x.c.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := x.c.Running(t.Context()); err != nil {
				t.Fatal(err)
			}
			if currentServer(x.c) != nil {
				t.Fatal("Running after Close created a listener")
			}
		}},
		"shutdown_join": {run: func(t *testing.T) {
			x := debugController(t, true, Config{})
			if err := setDebugAddress(t, x, "127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			g := currentServer(x.c)
			entered, exited := make(chan struct{}), make(chan struct{})
			g.server.Handler.(*http.ServeMux).HandleFunc("GET /owned-join", func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				pprof.Handler("heap").ServeHTTP(w, r)
				close(exited)
			})
			requestDone := make(chan struct{})
			go func() {
				defer close(requestDone)
				request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+g.address+"/owned-join?seconds=300", nil)
				if err != nil {
					t.Error(err)
					return
				}
				response, err := x.client.Do(request)
				if err == nil {
					if err := response.Body.Close(); err != nil {
						t.Error(err)
					}
				}
			}()
			select {
			case <-entered:
			case <-t.Context().Done():
				t.Fatal("owned handler not entered")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var closers sync.WaitGroup
			for range 2 {
				closers.Go(func() {
					if err := x.c.Close(ctx); err != nil {
						t.Error(err)
					}
				})
			}
			closers.Wait()
			assertServerJoined(t, g)
			select {
			case <-exited:
			default:
				t.Fatal("Close returned before active handler exited")
			}
			select {
			case <-requestDone:
			case <-ctx.Done():
				t.Fatal("owned client request did not finish")
			}
			select {
			case <-x.c.done:
			default:
				t.Fatal("controller worker did not join")
			}
			if !x.c.Status().Stopped || x.c.Status().Enabled {
				t.Fatal("closed status incorrect")
			}
		}},
	}
	t.Run("contracts", func(t *testing.T) {
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}
