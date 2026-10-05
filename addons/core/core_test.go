// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package core_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/core"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

// Upstream test/mitmproxy/addons/test_core.py maps without deferred cases:
// test_set -> TestSet; test_resume -> TestResume; test_mark -> TestMark;
// test_kill -> TestKill; test_revert -> TestRevert; test_flow_set -> TestFlowSet;
// test_encoding -> TestEncoding; test_options -> TestOptions;
// test_validation_simple -> TestValidationSimple; test_client_certs -> TestClientCerts.
// Native flow arguments exercise core independently of the view addon.

type updates struct {
	flows [][]string
}

func (u *updates) Update(ctx context.Context, flows []flow.Flow) error {
	if _, err := addon.Concurrent(ctx, func(context.Context) error { return nil }); !errors.Is(err, addon.ErrSyncContext) {
		return options.Errorf("core update did not run synchronously: %v", err)
	}
	ids := make([]string, len(flows))
	for i, f := range flows {
		ids[i] = f.Common().ID
	}
	u.flows = append(u.flows, ids)
	return nil
}

type harness struct {
	manager *addon.Manager
	updates *updates
}

func setup(t *testing.T) harness {
	t.Helper()
	previous := httpmsg.DecodeLimit()
	t.Cleanup(func() { httpmsg.SetDecodeLimit(previous) })
	m := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
	t.Cleanup(m.Close)
	u := &updates{}
	if err := m.Add(t.Context(), core.New(m), u); err != nil {
		t.Fatal(err)
	}
	return harness{m, u}
}

func (h harness) call(t *testing.T, name string, args ...any) any {
	t.Helper()
	result, err := h.manager.Call(t.Context(), name, args...)
	if err != nil {
		t.Fatalf("%s(%v): %v", name, args, err)
	}
	return result
}

func (h harness) wantUpdate(t *testing.T, flows ...flow.Flow) {
	t.Helper()
	want := make([]string, len(flows))
	for i, f := range flows {
		want[i] = f.Common().ID
	}
	if diff := gocmp.Diff([][]string{want}, h.updates.flows); diff != "" {
		t.Fatalf("update hooks (-want +got):\n%s", diff)
	}
	h.updates.flows = nil
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func TestSet(t *testing.T) {
	tests := map[string]struct {
		args []any
		want any
	}{
		"boolean false":          {[]any{"upstream_cert", "false"}, false},
		"boolean toggle":         {[]any{"upstream_cert", "toggle"}, false},
		"boolean omitted":        {[]any{"upstream_cert"}, true},
		"string value":           {[]any{"listen_host", "value"}, "value"},
		"sequence values append": {[]any{"ignore_hosts", "one", "two"}, []string{"one", "two"}},
		"sequence omitted":       {[]any{"ignore_hosts"}, []string{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			h.call(t, "set", tt.args...)
			if diff := gocmp.Diff(tt.want, h.manager.Options().Current(tt.args[0].(string))); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	h := setup(t)
	if _, err := h.manager.Call(t.Context(), "set", "nonexistent"); err == nil {
		t.Fatal("unknown option accepted")
	}
}

func TestResume(t *testing.T) {
	h := setup(t)
	f := testflow.TFlow()
	h.call(t, "flow.resume", []flow.Flow{f})
	h.wantUpdate(t)
	f.Intercept()
	h.call(t, "flow.resume", []flow.Flow{f})
	if f.Intercepted() {
		t.Fatal("flow remains intercepted")
	}
	h.wantUpdate(t, f)
	if err := f.WaitForResume(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestMark(t *testing.T) {
	h := setup(t)
	f := testflow.TFlow()
	h.call(t, "flow.mark", []flow.Flow{f}, command.Marker(":default:"))
	if f.Marked != ":default:" {
		t.Fatalf("marker = %q", f.Marked)
	}
	h.wantUpdate(t, f)
	if _, err := h.manager.Call(t.Context(), "flow.mark", []flow.Flow{f}, command.Marker("invalid")); err == nil || err.Error() != "invalid marker value" {
		t.Fatalf("invalid marker: %v", err)
	}
	if len(h.updates.flows) != 0 || f.Marked != ":default:" {
		t.Fatal("invalid marker changed flow or fired update")
	}
	for _, want := range []string{"", ":default:"} {
		h.call(t, "flow.mark.toggle", []flow.Flow{f})
		if f.Marked != want {
			t.Fatalf("marker = %q, want %q", f.Marked, want)
		}
		h.wantUpdate(t, f)
	}
	h.call(t, "flow.mark", []flow.Flow{f}, command.Marker(""))
	if f.Marked != "" {
		t.Fatalf("marker = %q", f.Marked)
	}
	h.wantUpdate(t, f)
}

func TestKill(t *testing.T) {
	logs := captureLogs(t)
	h := setup(t)
	live, finished := testflow.TFlow(), testflow.TTCPFlow()
	live.Intercept()
	finished.Live = false
	h.call(t, "flow.kill", []flow.Flow{live, finished, live})
	if live.Killable() || live.Intercepted() || live.Error == nil || live.Error.Msg != flow.KilledMessage {
		t.Fatalf("flow not killed: %+v", live)
	}
	h.wantUpdate(t, live)
	if !strings.Contains(logs.String(), "level=INFO+1 msg=\"Killed 1 flows.\"") {
		t.Fatalf("alert log missing: %s", logs)
	}
}

func TestRevert(t *testing.T) {
	logs := captureLogs(t)
	h := setup(t)
	f, unchanged := testflow.TFlow(), testflow.TFlow()
	original := slices.Clone(f.Request.RawContent)
	f.Backup()
	f.Request.SetContent([]byte("bar"))
	if !f.Modified() {
		t.Fatal("test flow did not change")
	}
	h.call(t, "flow.revert", []flow.Flow{f, unchanged, f})
	if f.Modified() {
		t.Fatal("flow remains modified")
	}
	if diff := gocmp.Diff(original, f.Request.RawContent); diff != "" {
		t.Fatal(diff)
	}
	h.wantUpdate(t, f)
	if !strings.Contains(logs.String(), "level=INFO+1 msg=\"Reverted 1 flows.\"") {
		t.Fatalf("alert log missing: %s", logs)
	}
}

func TestFlowSet(t *testing.T) {
	tests := map[string]struct {
		attr, value string
		want        string
		read        func(*flow.HTTPFlow) string
	}{
		"method":                        {"method", "post", "POST", func(f *flow.HTTPFlow) string { return strings.ToUpper(f.Request.Method) }},
		"host":                          {"host", "testhost", "testhost", func(f *flow.HTTPFlow) string { return f.Request.Host }},
		"path":                          {"path", "/test/path", "/test/path", func(f *flow.HTTPFlow) string { return f.Request.Path }},
		"url":                           {"url", "http://foo.com/bar", "http://foo.com/bar", func(f *flow.HTTPFlow) string { return f.Request.URL() }},
		"status":                        {"status_code", "404", "404 Not Found", func(f *flow.HTTPFlow) string { return fmt.Sprintf("%d %s", f.Response.StatusCode, f.Response.Reason) }},
		"unicode status":                {"status_code", " +٤_٠_٤ ", "404 Not Found", func(f *flow.HTTPFlow) string { return fmt.Sprintf("%d %s", f.Response.StatusCode, f.Response.Reason) }},
		"unknown status retains reason": {"status_code", "599", "599 OK", func(f *flow.HTTPFlow) string { return fmt.Sprintf("%d %s", f.Response.StatusCode, f.Response.Reason) }},
		"reason":                        {"reason", "foo", "foo", func(f *flow.HTTPFlow) string { return f.Response.Reason }},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			logs := captureLogs(t)
			h := setup(t)
			f := testflow.TFlow(testflow.WithResponse)
			h.call(t, "flow.set", []flow.Flow{f}, tt.attr, tt.value)
			if diff := gocmp.Diff(tt.want, tt.read(f)); diff != "" {
				t.Fatal(diff)
			}
			h.wantUpdate(t, f)
			if !strings.Contains(logs.String(), fmt.Sprintf("Set %s on  1 flows.", tt.attr)) {
				t.Fatalf("alert log missing: %s", logs)
			}
		})
	}
	h := setup(t)
	for _, attr := range []string{"url", "status_code"} {
		if _, err := h.manager.Call(t.Context(), "flow.set", []flow.Flow{testflow.TFlow(testflow.WithResponse)}, attr, "oink"); err == nil {
			t.Fatalf("invalid %s accepted", attr)
		}
	}
	if len(h.updates.flows) != 0 {
		t.Fatal("invalid input fired update")
	}
	want := []string{"host", "status_code", "method", "path", "url", "reason"}
	if diff := gocmp.Diff(want, h.call(t, "flow.set.options")); diff != "" {
		t.Fatal(diff)
	}
	// Upstream's request update flag stays true even for response-only fields.
	// Flows with no relevant message therefore still reach the update hook.
	f, tcp := testflow.TFlow(), testflow.TTCPFlow()
	h.call(t, "flow.set", []flow.Flow{f, tcp}, "reason", "unchanged")
	h.wantUpdate(t, f, tcp)
}

func TestEncoding(t *testing.T) {
	h := setup(t)
	f := testflow.TFlow()
	original := slices.Clone(f.Request.RawContent)
	if diff := gocmp.Diff([]string{"gzip", "deflate", "br", "zstd"}, h.call(t, "flow.encode.options")); diff != "" {
		t.Fatal(diff)
	}
	h.call(t, "flow.encode", []flow.Flow{f}, "request", "deflate")
	h.wantUpdate(t, f)
	h.call(t, "flow.encode", []flow.Flow{f}, "request", "br")
	h.wantUpdate(t)
	if got := f.Request.Headers.Get("content-encoding"); got != "deflate" {
		t.Fatalf("existing encoding changed: %q", got)
	}
	h.call(t, "flow.decode", []flow.Flow{f}, "request")
	h.wantUpdate(t, f)
	if f.Request.Headers.Has("content-encoding") {
		t.Fatal("decode left content-encoding")
	}
	h.call(t, "flow.encode", []flow.Flow{f}, "request", "br")
	h.wantUpdate(t, f)
	if got := f.Request.Headers.Get("content-encoding"); got != "br" {
		t.Fatalf("encoding = %q", got)
	}
	for _, want := range []string{"", "deflate", ""} {
		h.call(t, "flow.encode.toggle", []flow.Flow{f}, "request")
		h.wantUpdate(t, f)
		if got := f.Request.Headers.Get("content-encoding"); got != want {
			t.Fatalf("encoding = %q, want %q", got, want)
		}
	}
	if diff := gocmp.Diff(original, f.Request.RawContent); diff != "" {
		t.Fatal(diff)
	}
	h.call(t, "flow.revert", []flow.Flow{f})
	if f.Modified() || f.Request.Headers.Has("content-encoding") {
		t.Fatal("encoding backup did not restore original")
	}
}

func TestEncodingPartsAndErrors(t *testing.T) {
	tests := map[string]struct {
		name, part string
		args       []any
		encoding   string
		body       []byte
		wantErr    bool
	}{
		"decode malformed":            {"flow.decode", "response", nil, "gzip", []byte("bad"), true},
		"toggle malformed":            {"flow.encode.toggle", "response", nil, "gzip", []byte("bad"), true},
		"encode unsupported":          {"flow.encode", "response", []any{"unknown"}, "", []byte("body"), true},
		"decode absent":               {"flow.decode", "missing", nil, "", []byte("body"), false},
		"encode empty":                {"flow.encode", "response", []any{"gzip"}, "", []byte{}, false},
		"decode empty keeps encoding": {"flow.decode", "response", nil, "gzip", []byte{}, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			f := testflow.TFlow(testflow.WithResponse)
			f.Response.RawContent = slices.Clone(tt.body)
			if tt.encoding != "" {
				f.Response.Headers.Set("content-encoding", tt.encoding)
			}
			args := append([]any{[]flow.Flow{f, testflow.TTCPFlow()}, tt.part}, tt.args...)
			_, err := h.manager.Call(t.Context(), tt.name, args...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if len(h.updates.flows) != 0 {
					t.Fatal("failed encoding fired update")
				}
				if err := f.Revert(); err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(tt.body, f.Response.RawContent); diff != "" {
					t.Fatal(diff)
				}
			} else if tt.part == "missing" {
				h.wantUpdate(t)
			} else {
				h.wantUpdate(t, f)
				if tt.name == "flow.decode" && f.Response.Headers.Get("content-encoding") != tt.encoding {
					t.Fatal("empty decode changed encoding")
				}
			}
		})
	}
}

func TestOptions(t *testing.T) {
	h := setup(t)
	path := command.Path(filepath.Join(t.TempDir(), "options.yaml"))
	h.call(t, "set", "listen_host", "foo")
	h.call(t, "options.reset.one", "listen_host")
	if h.manager.Options().Str("listen_host") != "" {
		t.Fatal("reset one did not restore default")
	}
	if _, err := h.manager.Call(t.Context(), "options.reset.one", "unknown"); err == nil || err.Error() != "No such option: unknown" {
		t.Fatalf("unknown reset: %v", err)
	}
	h.call(t, "set", "listen_host", "foo")
	h.call(t, "options.save", path)
	if _, err := h.manager.Call(t.Context(), "options.save", command.Path(t.TempDir())); err == nil || !strings.HasPrefix(err.Error(), "Could not save options - ") {
		t.Fatalf("save directory: %v", err)
	}
	h.call(t, "options.reset")
	if h.manager.Options().Str("listen_host") != "" {
		t.Fatal("reset all did not restore default")
	}
	h.call(t, "options.load", path)
	if h.manager.Options().Str("listen_host") != "foo" {
		t.Fatal("load did not restore saved value")
	}
	h.call(t, "options.load", command.Path(filepath.Join(t.TempDir(), "nonexistent")))
	if err := os.WriteFile(string(path), []byte("listen_host: foo\n'''"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.Call(t.Context(), "options.load", path); err == nil || !strings.HasPrefix(err.Error(), "Could not load options - ") {
		t.Fatalf("invalid YAML: %v", err)
	}
}

func TestExecuteAndConcurrentCalls(t *testing.T) {
	h := setup(t)
	if _, err := h.manager.Commands().Execute(t.Context(), "flow.kill @all"); !errors.Is(err, command.ErrUnknownCommand) || !strings.Contains(err.Error(), "view.flows.resolve") || !strings.Contains(err.Error(), "@all") {
		t.Fatalf("missing view: %v", err)
	}
	f := testflow.TFlow()
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := h.manager.Commands().Call(t.Context(), "flow.mark.toggle", []flow.Flow{f}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if f.Marked != "" || len(h.updates.flows) != 20 {
		t.Fatalf("serialized toggles: marker=%q updates=%d", f.Marked, len(h.updates.flows))
	}
	if _, err := h.manager.Commands().Execute(t.Context(), "set upstream_cert false"); err != nil {
		t.Fatal(err)
	}
	if h.manager.Options().Bool("upstream_cert") {
		t.Fatal("Execute did not change option")
	}
	// Both choices return caller-owned slices, not mutable registry storage.
	for _, name := range []string{"flow.set.options", "flow.encode.options"} {
		first := h.call(t, name).([]string)
		want := slices.Clone(first)
		first[0] = "changed"
		if diff := gocmp.Diff(want, h.call(t, name)); diff != "" {
			t.Fatal(diff)
		}
	}
}

func TestCommandErrors(t *testing.T) {
	path := command.Path(filepath.Join(t.TempDir(), "invalid.yaml"))
	if err := os.WriteFile(string(path), []byte("listen_host: foo\n'''"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		name                                  string
		args                                  []any
		commandError, optionsError, pathError bool
	}{
		"unknown option":         {"set", []any{"unknown"}, true, true, false},
		"multiple scalar values": {"set", []any{"listen_host", "one", "two"}, true, true, false},
		"invalid boolean":        {"set", []any{"upstream_cert", "invalid"}, true, true, false},
		"invalid marker":         {"flow.mark", []any{[]flow.Flow{testflow.TFlow()}, command.Marker("invalid")}, true, false, false},
		"invalid URL":            {"flow.set", []any{[]flow.Flow{testflow.TFlow()}, "url", "invalid"}, true, false, false},
		"invalid status":         {"flow.set", []any{[]flow.Flow{testflow.TFlow()}, "status_code", "invalid"}, true, false, false},
		"unknown reset":          {"options.reset.one", []any{"unknown"}, true, false, false},
		"load malformed YAML":    {"options.load", []any{path}, true, true, false},
		"save directory":         {"options.save", []any{command.Path(t.TempDir())}, true, false, true},
		"save malformed YAML":    {"options.save", []any{path}, false, true, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			_, err := h.manager.Call(t.Context(), tt.name, tt.args...)
			if err == nil {
				t.Fatal("invalid input accepted")
			}
			if _, ok := errors.AsType[*command.Error](err); ok != tt.commandError {
				t.Fatalf("command error = %v, want %v: %v", ok, tt.commandError, err)
			}
			if _, ok := errors.AsType[*options.OptionsError](err); ok != tt.optionsError {
				t.Fatalf("options cause = %v, want %v: %v", ok, tt.optionsError, err)
			}
			if _, ok := errors.AsType[*os.PathError](err); ok != tt.pathError {
				t.Fatalf("path cause = %v, want %v: %v", ok, tt.pathError, err)
			}
			if h.manager.Options().Str("listen_host") != "" {
				t.Fatal("failed set changed the scalar option")
			}
		})
	}
}

func TestHTTPMutationBoundary(t *testing.T) {
	tests := map[string]struct {
		name string
		args []any
		set  bool
	}{
		"method":          {"flow.set", []any{"method", "post"}, true},
		"status":          {"flow.set", []any{"status_code", "404"}, true},
		"decode request":  {"flow.decode", []any{"request"}, false},
		"encode request":  {"flow.encode", []any{"request", "gzip"}, false},
		"toggle request":  {"flow.encode.toggle", []any{"request"}, false},
		"decode response": {"flow.decode", []any{"response"}, false},
		"encode response": {"flow.encode", []any{"response", "gzip"}, false},
		"toggle response": {"flow.encode.toggle", []any{"response"}, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			http := testflow.TFlow(testflow.WithResponse)
			empty := testflow.TFlow()
			empty.Request = nil
			unchanged := []flow.Flow{testflow.TTCPFlow(), testflow.TUDPFlow(), testflow.TDNSFlow(testflow.WithResponse), empty}
			before := make([]*state.Map, len(unchanged))
			for i, f := range unchanged {
				before[i] = f.GetState()
			}
			flows := append([]flow.Flow{http}, unchanged...)
			h.call(t, tt.name, append([]any{flows}, tt.args...)...)
			for i, f := range unchanged {
				if !state.Equal(before[i], f.GetState()) {
					t.Fatalf("%T was mutated", f)
				}
			}
			if tt.set {
				h.wantUpdate(t, flows...)
			} else {
				h.wantUpdate(t, http)
			}
		})
	}
}

func TestMethodPreservesWireBytes(t *testing.T) {
	h := setup(t)
	f := testflow.TFlow()
	h.call(t, "flow.set", []flow.Flow{f}, "method", "post")
	if diff := gocmp.Diff("post", f.Request.Method); diff != "" {
		t.Fatal(diff)
	}
	got, ok := f.Request.GetState().Get("method")
	if !ok {
		t.Fatal("serialized request lacks method")
	}
	if diff := gocmp.Diff([]byte("post"), got); diff != "" {
		t.Fatal(diff)
	}
}

func TestRegistrationLifetime(t *testing.T) {
	m := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
	t.Cleanup(m.Close)
	c := core.New(m)
	for range 2 {
		if err := m.Add(t.Context(), c); err != nil {
			t.Fatal(err)
		}
		count := 0
		for range m.Commands().Commands() {
			count++
		}
		if count != 16 {
			t.Fatalf("registered commands = %d, want 16", count)
		}
		if err := m.Remove(t.Context(), c); err != nil {
			t.Fatal(err)
		}
		for name := range m.Commands().Commands() {
			t.Fatalf("removed addon retained %s", name)
		}
		if _, err := m.Call(t.Context(), "flow.set.options"); !errors.Is(err, command.ErrUnknownCommand) {
			t.Fatalf("removed command: %v", err)
		}
	}
}

func TestHostAndURLDependentFields(t *testing.T) {
	h := setup(t)
	f := testflow.TFlow()
	f.Request.Headers = httpmsg.Headers{}
	f.Request.Headers.Set("Host", "old.example:80")
	f.Request.Authority = "old.example:80"
	h.call(t, "flow.set", []flow.Flow{f}, "url", "https://new.example:8443/path?q=1")
	if got := f.Request.Headers.Get("Host"); got != "new.example:8443" || f.Request.Authority != got {
		t.Fatalf("Host=%q authority=%q", got, f.Request.Authority)
	}
	h.call(t, "flow.set", []flow.Flow{f}, "host", "other.example")
	if got := f.Request.Headers.Get("Host"); got != "other.example:8443" || f.Request.Authority != got {
		t.Fatalf("Host=%q authority=%q", got, f.Request.Authority)
	}
}
