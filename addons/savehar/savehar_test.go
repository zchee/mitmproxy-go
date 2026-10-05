// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package savehar

import (
	"bytes"
	"compress/zlib"
	"context"
	json "encoding/json/v2"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/save"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

// Corresponds to test_write_error: exporting does not create missing parents.
func TestWriteError(t *testing.T) {
	a := New(options.New(), "1.2.3")
	if err := a.exportHAR(t.Context(), nil, command.Path(filepath.Join(t.TempDir(), "unknown", "out.har"))); err == nil {
		t.Fatal("missing parent accepted")
	}
}

func TestFilePermissions(t *testing.T) {
	tests := map[string]struct {
		suffix   string
		existing bool
		want     os.FileMode
	}{
		"success: new HAR":                 {suffix: ".har", want: 0o600},
		"success: new compressed HAR":      {suffix: ".zhar", want: 0o600},
		"success: existing HAR":            {suffix: ".har", existing: true, want: 0o640},
		"success: existing compressed HAR": {suffix: ".zhar", existing: true, want: 0o640},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "out"+tt.suffix)
			if tt.existing {
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, tt.want); err != nil {
					t.Fatal(err)
				}
			}
			if err := New(options.New(), "1.2.3").exportHAR(t.Context(), nil, command.Path(path)); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			// Windows does not expose Unix owner/group permission bits.
			if runtime.GOOS != "windows" {
				if diff := cmp.Diff(tt.want, info.Mode().Perm()); diff != "" {
					t.Error(diff)
				}
			}
		})
	}
}

// Covers every *.mitm fixture parameter of upstream test_savehar.
func TestExportFixtures(t *testing.T) {
	paths, err := filepath.Glob("../../testdata/mitmproxy/flows/*.mitm")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 7 {
		t.Fatalf("fixture count = %d, want 7", len(paths))
	}
	tests := make(map[string]struct{ path string }, len(paths))
	for _, path := range paths {
		tests[filepath.Base(path)] = struct{ path string }{path}
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			file, err := os.Open(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := file.Close(); err != nil {
					t.Error(err)
				}
			})
			var flows []flow.Flow
			for f, err := range flowio.NewReader(file).All() {
				if err != nil {
					t.Fatal(err)
				}
				flows = append(flows, f)
			}
			want, err := os.ReadFile(strings.TrimSuffix(tt.path, ".mitm") + ".har")
			if err != nil {
				t.Fatal(err)
			}
			path := command.Path(filepath.Join(t.TempDir(), "out.har"))
			if err := New(options.New(), "1.2.3").exportHAR(t.Context(), flows, path); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(string(path))
			if err != nil {
				t.Fatal(err)
			}
			var gotJSON, wantJSON any
			if err := json.Unmarshal(got, &gotJSON); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(want, &wantJSON); err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(wantJSON, gotJSON) {
				// Fixtures contain captured auth headers; do not print their values.
				t.Error("HAR export differs from the upstream fixture")
			}
		})
	}
}

// Corresponds to test_request_cookies and test_response_cookies.
func TestCookies(t *testing.T) {
	tests := map[string]struct {
		headers  httpmsg.Headers
		want     string
		response bool
	}{
		"success: request":             {headers: httpmsg.Headers{{Name: []byte("cookie"), Value: []byte("foo=bar")}}, want: `[{"name":"foo","value":"bar"}]`},
		"success: duplicate request":   {headers: httpmsg.Headers{{Name: []byte("cookie"), Value: []byte("foo=bar")}, {Name: []byte("cookie"), Value: []byte("foo=baz")}}, want: `[{"name":"foo","value":"bar"},{"name":"foo","value":"baz"}]`},
		"success: response":            {response: true, headers: httpmsg.Headers{{Name: []byte("set-cookie"), Value: []byte("foo=bar; path=/; domain=.googls.com; priority=high")}}, want: `[{"name":"foo","value":"bar","path":"/","domain":".googls.com","httpOnly":false,"secure":false}]`},
		"success: response attributes": {response: true, headers: httpmsg.Headers{{Name: []byte("set-cookie"), Value: []byte("foo=bar; path=/; domain=.googls.com; Secure; HttpOnly; priority=high")}, {Name: []byte("set-cookie"), Value: []byte("fooz=baz; path=/; domain=.googls.com; priority=high; SameSite=none")}}, want: `[{"name":"foo","value":"bar","path":"/","domain":".googls.com","httpOnly":true,"secure":true},{"name":"fooz","value":"baz","path":"/","domain":".googls.com","httpOnly":false,"secure":false,"sameSite":"none"}]`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := testflow.TFlow(testflow.WithResponse)
			f.Request.Headers, f.Response.Headers = tt.headers, tt.headers
			entry, err := flowEntry(f, make(map[*connection.Server]struct{}))
			if err != nil {
				t.Fatal(err)
			}
			message := entry["request"].(map[string]any)
			if tt.response {
				message = entry["response"].(map[string]any)
			}
			raw, err := json.Marshal(message["cookies"])
			if err != nil {
				t.Fatal(err)
			}
			var got, want any
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tt.want), &want); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Error(diff)
			}
		})
	}
}

// Corresponds to test_seen_server_conn, test_timestamp_end and test_tls_setup.
func TestTimings(t *testing.T) {
	tests := map[string]struct {
		seen, noEnd, noTLS bool
		field              string
		want               float64
	}{
		"success: reused connect": {seen: true, field: "connect", want: -1},
		"success: reused TLS":     {seen: true, field: "ssl", want: -1},
		"success: send":           {field: "send", want: 1000},
		"success: missing end":    {noEnd: true, field: "send", want: 0},
		"success: missing TLS":    {noTLS: true, field: "ssl", want: -1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := testflow.TWebSocketFlow()
			seen := make(map[*connection.Server]struct{})
			if tt.seen {
				seen[f.ServerConn] = struct{}{}
			}
			if tt.noEnd {
				f.Request.TimestampEnd = nil
			}
			if tt.noTLS {
				f.ServerConn.TimestampTLSSetup = nil
			}
			entry, err := flowEntry(f, seen)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, entry["timings"].(map[string]float64)[tt.field]); diff != "" {
				t.Error(diff)
			}
		})
	}
}

// Corresponds to test_binary_content, test_content_raises and test_flow_entry.
func TestContentAndConnect(t *testing.T) {
	tests := map[string]struct{ binary, invalidEncoding, connect bool }{
		"success: binary": {binary: true}, "success: corrupt encoding": {invalidEncoding: true}, "success: CONNECT": {connect: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := testflow.TFlow(testflow.WithResponse)
			if tt.binary {
				f.Response.Headers = nil
				f.Response.RawContent = append([]byte("foo"), bytes.Repeat([]byte{255}, 10)...)
			}
			if tt.invalidEncoding {
				f.Request.Headers.Set("Content-Encoding", "utf8")
				f.Response.Headers.Set("Content-Encoding", "utf8")
			}
			if tt.connect {
				r, err := httpmsg.MakeRequest("CONNECT", "https://test.test/", nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				f.Request = r
			}
			entry, err := flowEntry(f, make(map[*connection.Server]struct{}))
			if err != nil {
				t.Fatal(err)
			}
			if tt.binary {
				want := map[string]any{"size": 13, "compression": 0, "mimeType": "", "text": "Zm9v/////////////w==", "encoding": "base64"}
				if diff := cmp.Diff(want, entry["response"].(map[string]any)["content"]); diff != "" {
					t.Error(diff)
				}
			}
			if tt.connect && !strings.HasPrefix(entry["request"].(map[string]any)["url"].(string), "https") {
				t.Fatal("CONNECT URL is not HTTPS")
			}
		})
	}
}

func newContext(t *testing.T, a *Addon) (*addon.Manager, *options.Manager, *command.Manager) {
	t.Helper()
	opts, cmds := a.options, command.NewManager()
	manager := addon.NewManager(opts, cmds, addon.Config{})
	t.Cleanup(manager.Close)
	if err := manager.Add(t.Context(), save.New(opts, nil), a); err != nil {
		t.Fatal(err)
	}
	return manager, opts, cmds
}

// TestHardump covers test_simple, test_filter, test_free and test_compressed.
func TestHardump(t *testing.T) {
	tests := map[string]struct {
		filter, free, compressed bool
		count                    int
	}{
		"success: simple": {count: 3}, "success: filter": {filter: true, count: 1}, "success: free": {free: true, count: 0}, "success: compressed": {compressed: true, count: 3},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout bytes.Buffer
			a := New(options.New(), "1.2.3")
			a.stdout = &stdout
			manager, opts, _ := newContext(t, a)
			path := "-"
			if tt.compressed {
				path = filepath.Join(t.TempDir(), "out.zhar")
			}
			if err := manager.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"hardump": path}) }); err != nil {
				t.Fatal(err)
			}
			if tt.filter {
				if err := manager.Do(t.Context(), func(ctx context.Context) error { return opts.Set(ctx, "save_stream_filter=~~") }); err == nil {
					t.Fatal("invalid filter accepted")
				}
				if err := manager.Do(t.Context(), func(ctx context.Context) error { return opts.Set(ctx, "save_stream_filter=~b foo") }); err != nil {
					t.Fatal(err)
				}
			}
			first := testflow.TFlow()
			first.Request.RawContent = []byte("foo")
			if err := manager.Trigger(t.Context(), addon.ResponseHook{Flow: first}); err != nil {
				t.Fatal(err)
			}
			if err := manager.Trigger(t.Context(), addon.ErrorHook{Flow: testflow.TFlow()}); err != nil {
				t.Fatal(err)
			}
			ws := testflow.TWebSocketFlow()
			if err := manager.Trigger(t.Context(), addon.ResponseHook{Flow: ws}); err != nil {
				t.Fatal(err)
			}
			if err := manager.Trigger(t.Context(), addon.WebSocketEndHook{Flow: ws}); err != nil {
				t.Fatal(err)
			}
			if tt.free {
				if err := manager.Do(t.Context(), func(ctx context.Context) error {
					if len(a.flows) == 0 {
						t.Error("no retained flows")
					}
					return opts.Set(ctx, "hardump=")
				}); err != nil {
					t.Fatal(err)
				}
				if len(a.flows) != 0 {
					t.Fatal("flows were not freed")
				}
			}
			if err := manager.Trigger(t.Context(), addon.DoneHook{}); err != nil {
				t.Fatal(err)
			}
			if tt.free {
				if stdout.Len() != 0 {
					t.Fatal("disabled hardump wrote output")
				}
				return
			}
			data := stdout.Bytes()
			if tt.compressed {
				compressed, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				reader, err := zlib.NewReader(bytes.NewReader(compressed))
				if err != nil {
					t.Fatal(err)
				}
				data, err = io.ReadAll(reader)
				if err != nil {
					t.Fatal(err)
				}
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
			}
			var doc struct {
				Log struct {
					Entries []any `json:"entries"`
				} `json:"log"`
			}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.count, len(doc.Log.Entries)); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestConcurrentCollection(t *testing.T) {
	var stdout bytes.Buffer
	a := New(options.New(), "1.2.3")
	a.stdout = &stdout
	manager, opts, cmds := newContext(t, a)
	if err := manager.Do(t.Context(), func(ctx context.Context) error { return opts.Set(ctx, "hardump=-") }); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 32)
	for range 32 {
		f := testflow.TFlow(testflow.WithResponse)
		go func() { results <- manager.Trigger(t.Context(), addon.ResponseHook{Flow: f}) }()
	}
	for range 32 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	path := command.Path(filepath.Join(t.TempDir(), "command.har"))
	if _, err := cmds.Call(t.Context(), "save.har", []flow.Flow{testflow.TFlow()}, path); err != nil {
		t.Fatal(err)
	}
	if err := manager.Trigger(t.Context(), addon.DoneHook{}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Log struct {
			Entries []any `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(32, len(doc.Log.Entries)); diff != "" {
		t.Error(diff)
	}
}

func TestMalformedFlow(t *testing.T) {
	tests := map[string]struct{ flow *flow.HTTPFlow }{
		"error: nil flow":   {},
		"error: no request": {flow: &flow.HTTPFlow{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := flowEntry(tt.flow, make(map[*connection.Server]struct{})); err == nil {
				t.Fatal("malformed flow accepted")
			}
		})
	}
}

func TestRegistration(t *testing.T) {
	a := New(options.New(), "1.2.3")
	_, opts, cmds := newContext(t, a)
	tests := map[string]struct {
		typ  options.Type
		def  any
		help string
	}{
		"hardump": {options.TypeStr, "", "Save a HAR file with all flows on exit. You may select particular flows by setting save_stream_filter. For mitmdump, enabling this option will mean that flows are kept in memory."},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opt, ok := opts.Lookup(name)
			if !ok {
				t.Fatal("option missing")
			}
			if diff := cmp.Diff(tt.typ, opt.Type()); diff != "" {
				t.Error(diff)
			}
			if diff := cmp.Diff(tt.def, opt.Default()); diff != "" {
				t.Error(diff)
			}
			if diff := cmp.Diff(tt.help, opt.Help()); diff != "" {
				t.Error(diff)
			}
		})
	}
	found := false
	for name, c := range cmds.Commands() {
		if name == "save.har" {
			found = true
			if diff := cmp.Diff("save.har flows path", c.SignatureHelp()); diff != "" {
				t.Error(diff)
			}
			if diff := cmp.Diff("Export flows to an HAR (HTTP Archive) file.", c.Help); diff != "" {
				t.Error(diff)
			}
			if len(c.Params) != 2 || c.Params[0].Type != command.FlowsType || c.Params[1].Type != command.PathType || c.Return != nil {
				t.Fatal("wrong command types")
			}
		}
	}
	if !found {
		t.Fatal("save.har missing")
	}
}
