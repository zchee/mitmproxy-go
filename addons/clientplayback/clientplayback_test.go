// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package clientplayback

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

func setup(t *testing.T) (*master.Master, *ClientPlayback) {
	t.Helper()
	m := master.New(master.Config{})
	c := New(m)
	if err := m.Addons.Add(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	return m, c
}

// test_check is represented by TestCheck; test_start_stop by TestStartStop;
// test_load and test_configure by TestLoadAndConfigure. Network test_playback
// and test_playback_https_upstream are covered in integration_test.go.
// test_playback_crash monkeypatches a Python method: the Go integration tests
// instead exercise real transport failures and ensure the worker retires.
func TestCheck(t *testing.T) {
	tests := map[string]struct {
		change func(*flow.HTTPFlow)
		other  bool
		want   string
	}{
		"success: complete HTTP":  {},
		"error: live":             {change: func(f *flow.HTTPFlow) { f.Live = true }, want: "Can't replay live flow."},
		"error: intercepted":      {change: func(f *flow.HTTPFlow) { f.Intercept() }, want: "Can't replay intercepted flow."},
		"error: missing request":  {change: func(f *flow.HTTPFlow) { f.Request = nil }, want: "Can't replay flow with missing request."},
		"error: missing content":  {change: func(f *flow.HTTPFlow) { f.Request.RawContent = nil }, want: "Can't replay flow with missing content."},
		"error: websocket":        {change: func(f *flow.HTTPFlow) { f.WebSocket = testflow.TWebSocketFlow().WebSocket }, want: "Can't replay WebSocket flows."},
		"success: complete HTTP2": {change: func(f *flow.HTTPFlow) { f.Request.HTTPVersion = "HTTP/2.0" }},
		"error: HTTP3":            {change: func(f *flow.HTTPFlow) { f.Request.HTTPVersion = "HTTP/3" }, want: "Can't replay HTTP/3 flows: HTTP/3 is not supported yet."},
		"error: other":            {other: true, want: "Can only replay HTTP flows."},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, c := setup(t)
			f := testflow.TFlow(testflow.WithResponse)
			f.Live = false
			if tt.change != nil {
				tt.change(f)
			}
			var input flow.Flow = f
			if tt.other {
				other := testflow.TTCPFlow()
				other.Live = false
				input = other
			}
			if err := m.Do(t.Context(), func(context.Context) error {
				if diff := cmp.Diff(tt.want, c.check(input)); diff != "" {
					t.Fatal(diff)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStartStop(t *testing.T) {
	m, c := setup(t)
	f := testflow.TFlow(testflow.WithResponse)
	f.Live = false
	before := f.GetState()
	if _, err := m.Call(t.Context(), "replay.client", []flow.Flow{f, f}); err != nil {
		t.Fatal(err)
	}
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		if c.count(ctx) != 1 || f.Response != nil || f.IsReplay == nil || *f.IsReplay != "request" {
			t.Fatal("flow was not queued once and prepared")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Call(t.Context(), "replay.client.stop"); err != nil {
		t.Fatal(err)
	}
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		if c.count(ctx) != 0 {
			t.Fatal("queue not cleared")
		}
		if diff := cmp.Diff(before, f.GetState()); diff != "" {
			t.Fatal(diff)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAndConfigure(t *testing.T) {
	m, c := setup(t)
	path := filepath.Join(t.TempDir(), "flows")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f := testflow.TFlow(testflow.WithResponse)
	f.Live = false
	if err := flowio.NewWriter(file).Add(f); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Call(t.Context(), "replay.client.file", command.Path(path)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Call(t.Context(), "replay.client.file", command.Path(path+"missing")); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		return m.Options.Update(ctx, map[string]any{"client_replay": []string{path}})
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		if c.count(ctx) != 2 {
			t.Fatalf("count=%d", c.count(ctx))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		value int
		valid bool
	}{"success: sequential": {1, true}, "success: concurrent": {-1, true}, "error: invalid": {-2, false}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := m.Do(t.Context(), func(ctx context.Context) error {
				return m.Options.Update(ctx, map[string]any{"client_replay_concurrency": tt.value})
			})
			if (err == nil) != tt.valid {
				t.Fatalf("validation: %v", err)
			}
			if !tt.valid && !strings.Contains(err.Error(), "Currently the only valid client_replay_concurrency values are -1 and 1.") {
				t.Fatal(err)
			}
		})
	}
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		return m.Options.Update(ctx, map[string]any{"client_replay": []string{path + "missing"}})
	}); err == nil {
		t.Fatal("missing configured file accepted")
	}
}

func TestInvalidReplayFiles(t *testing.T) {
	tests := map[string]struct {
		content   string
		oversized bool
	}{
		"error: truncated length": {content: "100:"},
		"error: invalid type":     {content: "1:x!"},
		"error: oversized file":   {oversized: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, c := setup(t)
			path := filepath.Join(t.TempDir(), "invalid.mitm")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			if tt.oversized {
				if err := file.Truncate(maxReplayBytes + 1); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := file.WriteString(tt.content); err != nil {
					t.Fatal(err)
				}
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Call(t.Context(), "replay.client.file", command.Path(path)); err == nil {
				t.Fatal("invalid file accepted")
			}
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				if c.count(ctx) != 0 {
					t.Fatal("failed file load changed queue")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTables(t *testing.T) {
	m, _ := setup(t)
	tests := map[string]struct {
		typ  options.Type
		def  any
		help string
	}{
		"client_replay":             {options.TypeSeq, []string{}, "Replay client requests from a saved file."},
		"client_replay_concurrency": {options.TypeInt, 1, "Concurrency limit on in-flight client replay requests. Currently the only valid values are 1 and -1 (no limit)."},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opt, ok := m.Options.Lookup(name)
			if !ok || opt.Type() != tt.typ {
				t.Fatal("missing option or wrong type")
			}
			if diff := cmp.Diff(tt.def, opt.Default()); diff != "" {
				t.Fatal(diff)
			}
			if diff := cmp.Diff(tt.help, opt.Help()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	want := map[string]string{"replay.client": "replay.client flows:flow[]", "replay.client.stop": "replay.client.stop", "replay.client.count": "replay.client.count -> int", "replay.client.file": "replay.client.file path:path"}
	got := map[string]string{}
	for name, c := range m.Commands.Commands() {
		parts := []string{name}
		for _, p := range c.Params {
			parts = append(parts, p.Name+":"+p.Type.Display())
		}
		if c.Return != nil {
			parts = append(parts, "->", c.Return.Display())
		}
		got[name] = strings.Join(parts, " ")
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}
}
