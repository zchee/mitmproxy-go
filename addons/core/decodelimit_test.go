// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package core_test

import (
	"context"
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/httpmsg"
	netencoding "github.com/zchee/mitmproxy-go/internal/netutil/encoding"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func TestDecodeLimitPublication(t *testing.T) {
	h := setup(t)
	f := testflow.TFlow()
	f.Request.SetContent([]byte("four"))
	if err := f.Request.Encode("gzip"); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		value       string
		limit       int64
		undecodable bool
	}{
		"zero is not unlimited": {"0", 0, true},
		"body exceeds bound":    {"3", 3, true},
		"body equals bound":     {"4", 4, false},
		"size suffix":           {"1k", 1024, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			previous := httpmsg.DecodeLimit()
			t.Cleanup(func() { httpmsg.SetDecodeLimit(previous) })
			h.call(t, "set", "content_decode_limit", tt.value)
			if got := httpmsg.DecodeLimit(); got != tt.limit {
				t.Fatalf("published limit = %d, want %d", got, tt.limit)
			}
			body, err := f.Request.Content()
			if tt.undecodable {
				if !errors.Is(err, netencoding.ErrSizeLimit) {
					t.Fatalf("decode over bound: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff([]byte("four"), body); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
	h.call(t, "options.reset.one", "content_decode_limit")
	if got := httpmsg.DecodeLimit(); got != 256<<20 {
		t.Fatalf("reset published %d, want 256 MiB", got)
	}
}

type rejectingLimit struct{ opts *options.Manager }

func (r *rejectingLimit) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, ok := updated["content_decode_limit"]; ok && r.opts.Str("content_decode_limit") == "2k" {
		return options.Errorf("limit refused by another addon")
	}
	return nil
}

func TestDecodeLimitRollback(t *testing.T) {
	h := setup(t)
	h.call(t, "set", "content_decode_limit", "1k")
	if err := h.manager.Add(t.Context(), &rejectingLimit{opts: h.manager.Options()}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"-1", "invalid", "2k"} {
		if err := updateOptions(t, h, map[string]any{"content_decode_limit": value}); err == nil {
			t.Fatalf("accepted rejected value %q", value)
		}
		if got := httpmsg.DecodeLimit(); got != 1024 {
			t.Fatalf("rejected %q left limit %d, want 1024", value, got)
		}
		if got := h.manager.Options().Str("content_decode_limit"); got != "1k" {
			t.Fatalf("rollback option = %q", got)
		}
	}
}

func TestDecodeLimitProcessGlobal(t *testing.T) {
	first, second := setup(t), setup(t)
	first.call(t, "set", "content_decode_limit", "1k")
	second.call(t, "set", "content_decode_limit", "2k")
	first.call(t, "set", "listen_host", "example.test")
	if got := httpmsg.DecodeLimit(); got != 2048 {
		t.Fatalf("last configure lost its limit: %d", got)
	}
	if err := first.manager.Trigger(t.Context(), addon.ConfigureHook{Updated: map[string]struct{}{"content_decode_limit": {}}}); err != nil {
		t.Fatal(err)
	}
	if got := httpmsg.DecodeLimit(); got != 1024 {
		t.Fatalf("explicit configure did not republish: %d", got)
	}
	if err := second.manager.Clear(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := httpmsg.DecodeLimit(); got != 256<<20 {
		t.Fatalf("done restored %d, want 256 MiB despite another manager", got)
	}
}

func TestDecodeLimitDone(t *testing.T) {
	tests := map[string]struct {
		done func(context.Context, *addon.Manager) error
	}{
		"done hook": {func(ctx context.Context, m *addon.Manager) error { return m.Trigger(ctx, addon.DoneHook{}) }},
		"remove":    {func(ctx context.Context, m *addon.Manager) error { return m.Remove(ctx, m.Get("core")) }},
		"clear":     {func(ctx context.Context, m *addon.Manager) error { return m.Clear(ctx) }},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			h.call(t, "set", "content_decode_limit", "1k")
			if err := tt.done(t.Context(), h.manager); err != nil {
				t.Fatal(err)
			}
			if got := httpmsg.DecodeLimit(); got != 256<<20 {
				t.Fatalf("done limit = %d, want 256 MiB", got)
			}
		})
	}
}
