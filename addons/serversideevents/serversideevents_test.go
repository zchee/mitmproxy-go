// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package serversideevents

import (
	"bytes"
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func TestResponse(t *testing.T) {
	const warning = "mitmproxy currently does not support server side events. As a workaround, you can enable response streaming for such flows: https://github.com/mitmproxy/mitmproxy/issues/4469"
	tests := map[string]struct {
		contentType string
		stream      bool
		transform   bool
		warn        bool
	}{
		"test_simple":           {"text/event-stream", false, false, true},
		"parameters":            {"text/event-stream; charset=utf-8", false, false, true},
		"upstream prefix rule":  {"text/event-streaming", false, false, true},
		"streaming":             {"text/event-stream", true, false, false},
		"transform":             {"text/event-stream", false, true, false},
		"different type":        {"text/plain", false, false, false},
		"no type":               {"", false, false, false},
		"case-sensitive prefix": {"Text/Event-Stream", false, false, false},
		"leading space":         {" text/event-stream", false, false, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(previous) })
			manager := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{})
			defer manager.Close()
			if err := manager.Add(t.Context(), &ServerSideEvents{}); err != nil {
				t.Fatal(err)
			}
			f := testflow.TFlow(testflow.WithResponse)
			if tt.contentType != "" {
				f.Response.Headers.Set("content-type", tt.contentType)
			}
			f.Response.Stream = tt.stream
			if tt.transform {
				f.Response.StreamFunc = func([]byte) [][]byte {
					t.Error("warning addon invoked the streaming transform")
					return nil
				}
			}
			body := slices.Clone(f.Response.RawContent)
			if err := manager.Trigger(t.Context(), addon.ResponseHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.warn, strings.Contains(logs.String(), warning)); diff != "" {
				t.Fatalf("warning mismatch: %s\nlogs: %s", diff, logs.String())
			}
			wantLogs := 0
			if tt.warn {
				wantLogs = 1
			}
			if diff := cmp.Diff(wantLogs, strings.Count(logs.String(), "level=WARN")); diff != "" {
				t.Fatal(diff)
			}
			if f.Response.Stream != tt.stream || (f.Response.StreamFunc != nil) != tt.transform {
				t.Fatal("warning addon changed streaming configuration")
			}
			if diff := cmp.Diff(body, f.Response.RawContent); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestContract(t *testing.T) {
	manager := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{})
	defer manager.Close()
	s := &ServerSideEvents{}
	if err := manager.Add(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	if len(manager.Options().Items()) != 0 {
		t.Fatal("unexpected option")
	}
	for name := range manager.Commands().Commands() {
		t.Fatalf("unexpected command %s", name)
	}
	if err := manager.Do(t.Context(), func(ctx context.Context) error {
		if err := s.Response(ctx, testflow.TFlow()); err == nil {
			t.Fatal("missing response accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
