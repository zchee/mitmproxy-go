// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package serverplayback

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

func setup(t *testing.T) (*master.Master, *ServerPlayback) {
	t.Helper()
	m := master.New(master.Config{})
	t.Cleanup(func() {
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	s := New(m)
	if err := m.Addons.Add(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	return m, s
}

func TestHash(t *testing.T) {
	// Cases correspond to upstream test_ignore_host, test_ignore_content,
	// test_ignore_content_wins_over_params, test_ignore_payload_params_other_content_type,
	// test_hash, test_headers, test_ignore_params and test_ignore_payload_params.
	tests := map[string]struct {
		opts   map[string]any
		change func(*flow.HTTPFlow)
		equal  bool
	}{
		"success: identical":                       {equal: true},
		"success: unselected header":               {change: func(f *flow.HTTPFlow) { f.Request.Headers.Set("foo", "bar") }, equal: true},
		"error: changed path":                      {change: func(f *flow.HTTPFlow) { f.Request.Path = "voing" }},
		"error: blank query value":                 {change: func(f *flow.HTTPFlow) { f.Request.Path += "?blank_value" }},
		"success: ignore host":                     {opts: map[string]any{"server_replay_ignore_host": true}, change: func(f *flow.HTTPFlow) { f.Request.Host = "wrong_address"; f.Request.RemoveHostHeader() }, equal: true},
		"error: changed content":                   {change: func(f *flow.HTTPFlow) { f.Request.RawContent = []byte("bar") }},
		"success: ignore content":                  {opts: map[string]any{"server_replay_ignore_content": true}, change: func(f *flow.HTTPFlow) { f.Request.RawContent = nil }, equal: true},
		"success: ignore content wins over params": {opts: map[string]any{"server_replay_ignore_content": true, "server_replay_ignore_payload_params": []string{"param1", "param2"}}, change: func(f *flow.HTTPFlow) { f.Request.SetURLEncodedForm([][2]string{{"paramx", "y"}}) }, equal: true},
		"error: ignore params does not ignore JSON": {opts: map[string]any{"server_replay_ignore_payload_params": []string{"param1"}}, change: func(f *flow.HTTPFlow) {
			f.Request.Headers.Set("Content-Type", "application/json")
			f.Request.RawContent = []byte(`{"param1":"2"}`)
		}},
		"error: selected missing header":          {opts: map[string]any{"server_replay_use_headers": []string{"foo"}}, change: func(f *flow.HTTPFlow) { f.Request.Headers.Set("foo", "bar") }},
		"success: selected missing headers match": {opts: map[string]any{"server_replay_use_headers": []string{"foo"}}, equal: true},
		"success: ignore query params":            {opts: map[string]any{"server_replay_ignore_params": []string{"param1", "param2"}}, change: func(f *flow.HTTPFlow) { f.Request.Path += "?param1=1&param2=2" }, equal: true},
		"error: retain query params":              {opts: map[string]any{"server_replay_ignore_params": []string{"param1", "param2"}}, change: func(f *flow.HTTPFlow) { f.Request.Path += "?param3=2" }},
		"success: ignore port":                    {opts: map[string]any{"server_replay_ignore_port": true}, change: func(f *flow.HTTPFlow) { f.Request.Port++ }, equal: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, s := setup(t)
			if err := m.Do(t.Context(), func(ctx context.Context) error { return m.Options.Update(ctx, tt.opts) }); err != nil {
				t.Fatal(err)
			}
			a, b := testflow.TFlow(), testflow.TFlow()
			if tt.change != nil {
				tt.change(b)
			}
			if got := s.hash(a) == s.hash(b); got != tt.equal {
				t.Fatalf("hash equality=%v want %v", got, tt.equal)
			}
		})
	}
}

func TestPayloadParams(t *testing.T) {
	tests := map[string]struct{ multipart bool }{"success: urlencoded": {}, "success: multipart": {multipart: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, s := setup(t)
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				return m.Options.Update(ctx, map[string]any{"server_replay_ignore_payload_params": []string{"param1", "param2"}})
			}); err != nil {
				t.Fatal(err)
			}
			setter := func(f *flow.HTTPFlow, pairs [][2]string) {
				if !tt.multipart {
					f.Request.SetURLEncodedForm(pairs)
					return
				}
				parts := make([][2][]byte, len(pairs))
				for i, p := range pairs {
					parts[i] = [2][]byte{[]byte(p[0]), []byte(p[1])}
				}
				if err := f.Request.SetMultipartForm(parts); err != nil {
					t.Fatal(err)
				}
			}
			a, b := testflow.TFlow(), testflow.TFlow()
			setter(a, [][2]string{{"paramx", "x"}, {"param1", "1"}})
			for _, pairs := range [][][2]string{{{"paramx", "x"}, {"param1", "1"}}, {{"paramx", "x"}, {"param1", "2"}}, {{"paramx", "x"}}, {{"paramx", "x"}, {"param2", "2"}}} {
				setter(b, pairs)
				if s.hash(a) != s.hash(b) {
					t.Fatalf("ignored payload params changed hash: %v", pairs)
				}
			}
			setter(b, [][2]string{{"paramx", "y"}, {"param1", "1"}})
			if s.hash(a) == s.hash(b) {
				t.Fatal("changed nonignored payload matched")
			}
			setter(b, [][2]string{{"param1", "1"}})
			if s.hash(a) == s.hash(b) {
				t.Fatal("missing nonignored payload matched")
			}
		})
	}
}

func TestServerPlayback(t *testing.T) {
	tests := map[string]struct {
		reuse   bool
		deleted bool
	}{"success: load add pop clear": {}, "success: reuse": {reuse: true}, "success: deleted responses": {deleted: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, s := setup(t)
			err := m.Do(t.Context(), func(ctx context.Context) error {
				if err := m.Options.Update(ctx, map[string]any{"server_replay_reuse": tt.reuse}); err != nil {
					return err
				}
				a, b := testflow.TFlow(testflow.WithResponse), testflow.TFlow(testflow.WithResponse)
				a.Request.Headers.Set("key", "one")
				b.Request.Headers.Set("key", "two")
				if err := s.loadFlows(ctx, []flow.Flow{a}); err != nil {
					return err
				}
				if err := s.addFlows(ctx, []flow.Flow{b, testflow.TTCPFlow()}); err != nil {
					return err
				}
				if got := s.count(ctx); got != 2 {
					t.Fatalf("count=%d want 2", got)
				}
				if tt.deleted {
					a.Response = nil
					b.Response = nil
					if s.nextFlow(a) != nil {
						t.Fatal("deleted response returned")
					}
					if s.count(ctx) != 0 {
						t.Fatal("deleted flows retained")
					}
				} else {
					if got := s.nextFlow(a); got != a {
						t.Fatalf("first flow=%p want %p", got, a)
					}
					if tt.reuse {
						if s.count(ctx) != 2 {
							t.Fatal("reuse popped flow")
						}
					} else {
						if s.nextFlow(a) != b || s.count(ctx) != 0 || s.nextFlow(a) != nil {
							t.Fatal("FIFO replay mismatch")
						}
					}
				}
				return s.clear(ctx)
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRuntimeModifyParams(t *testing.T) {
	m, s := setup(t)
	a, b := testflow.TFlow(testflow.WithResponse), testflow.TFlow()
	a.Request.Path = "/test?param1=1"
	b.Request.Path = "/test"
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		if err := s.loadFlows(ctx, []flow.Flow{a}); err != nil {
			return err
		}
		before := s.hash(a)
		if err := m.Options.Update(ctx, map[string]any{"server_replay_ignore_params": []string{"param1"}}); err != nil {
			return err
		}
		if s.hash(a) == before || s.nextFlow(b) != a {
			t.Fatal("hash map was not rebuilt")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRequest(t *testing.T) {
	tests := map[string]struct {
		opts   map[string]any
		match  bool
		status int
		kill   bool
	}{
		"success: server playback full": {match: true, status: 200}, "success: forward unmatched": {}, "success: deprecated kill": {opts: map[string]any{"server_replay_kill_extra": true}, kill: true}, "success: kill": {opts: map[string]any{"server_replay_extra": "kill"}, kill: true}, "success: 204": {opts: map[string]any{"server_replay_extra": "204"}, status: 204}, "success: 400": {opts: map[string]any{"server_replay_extra": "400"}, status: 400}, "success: 404": {opts: map[string]any{"server_replay_extra": "404"}, status: 404}, "success: 500": {opts: map[string]any{"server_replay_extra": "500"}, status: 500},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, s := setup(t)
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				if err := m.Options.Update(ctx, tt.opts); err != nil {
					return err
				}
				a, b := testflow.TFlow(testflow.WithResponse), testflow.TFlow()
				if !tt.match {
					b.Request.RawContent = []byte("gibble")
				}
				if err := s.loadFlows(ctx, []flow.Flow{a, a}); err != nil {
					return err
				}
				if err := s.Request(ctx, b); err != nil {
					return err
				}
				if (b.Error != nil) != tt.kill {
					t.Fatalf("error=%v kill=%v", b.Error, tt.kill)
				}
				if tt.status != 0 {
					if b.Response == nil || b.Response.StatusCode != tt.status || b.IsReplay == nil || *b.IsReplay != "response" {
						t.Fatalf("replay response=%v", b.Response)
					}
					if tt.match {
						if b.Response == a.Response {
							t.Fatal("response not cloned")
						}
						if diff := cmp.Diff(a.Response.GetState(), b.Response.GetState()); diff != "" {
							t.Fatal(diff)
						}
					}
				} else if b.Response != nil {
					t.Fatal("unexpected response")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLoadFileAndConfig(t *testing.T) {
	m, s := setup(t)
	path := filepath.Join(t.TempDir(), "flows")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := flowio.NewWriter(file).Add(testflow.TFlow(testflow.WithResponse)); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Call(t.Context(), "replay.server.file", command.Path(path)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Call(t.Context(), "replay.server.file", command.Path(path+"missing")); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		return m.Options.Update(ctx, map[string]any{"server_replay": []string{path}})
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		s.configured = false
		return m.Options.Update(ctx, map[string]any{"server_replay": []string{t.TempDir()}})
	}); err == nil {
		t.Fatal("directory accepted")
	}
}

func TestReplayFileLimit(t *testing.T) {
	m, _ := setup(t)
	path := filepath.Join(t.TempDir(), "oversized")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxReplayBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Call(t.Context(), "replay.server.file", command.Path(path)); err == nil || !strings.Contains(err.Error(), "512 MiB") {
		t.Fatalf("oversized sparse replay file: %v", err)
	}
}

func TestTables(t *testing.T) {
	m, _ := setup(t)
	tests := map[string]struct {
		typ options.Type
		def any
	}{
		"server_replay_kill_extra": {options.TypeBool, false}, "server_replay_extra": {options.TypeStr, "forward"}, "server_replay_reuse": {options.TypeBool, false}, "server_replay_nopop": {options.TypeBool, false}, "server_replay_refresh": {options.TypeBool, true}, "server_replay_use_headers": {options.TypeSeq, []string{}}, "server_replay": {options.TypeSeq, []string{}}, "server_replay_ignore_content": {options.TypeBool, false}, "server_replay_ignore_params": {options.TypeSeq, []string{}}, "server_replay_ignore_payload_params": {options.TypeSeq, []string{}}, "server_replay_ignore_host": {options.TypeBool, false}, "server_replay_ignore_port": {options.TypeBool, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			o, ok := m.Options.Lookup(name)
			if !ok || o.Type() != tt.typ {
				t.Fatalf("option type=%v want %v", o.Type(), tt.typ)
			}
			if diff := cmp.Diff(tt.def, o.Default()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	want := map[string]string{"replay.server": "replay.server flows:flow[]", "replay.server.add": "replay.server.add flows:flow[]", "replay.server.file": "replay.server.file path:path", "replay.server.stop": "replay.server.stop", "replay.server.count": "replay.server.count -> int"}
	got := map[string]string{}
	for name, c := range m.Commands.Commands() {
		parts := []string{name}
		for _, param := range c.Params {
			parts = append(parts, param.Name+":"+param.Type.Display())
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
