// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package eventstore

import (
	"log/slog"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
)

func TestEventStoreObservers(t *testing.T) {
	tests := map[string]struct{ size int }{
		"zero retention":   {size: 0},
		"ring replacement": {size: 1},
		"normal retention": {size: 4},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, err := New(tt.size)
			if err != nil {
				t.Fatal(err)
			}
			other, err := New()
			if err != nil {
				t.Fatal(err)
			}
			var observed []Event
			cancel := s.Observe(func(e Event) { observed = append(observed, e) })
			s.Observe(nil)()
			if err := other.AddLog(t.Context(), addon.LogEntry{Msg: "unrelated"}); err != nil {
				t.Fatal(err)
			}
			if len(observed) != 0 {
				t.Fatal("observer leaked across instances")
			}
			queued, unsubscribe := s.Subscribe(8)
			first := addon.LogEntry{Msg: "first", Level: slog.LevelInfo}
			second := addon.LogEntry{Msg: "second", Level: slog.LevelWarn}
			if err := s.AddLog(t.Context(), first); err != nil {
				t.Fatal(err)
			}
			if len(observed) != 1 {
				t.Fatal("observer was not synchronous")
			}
			if err := s.AddLog(t.Context(), second); err != nil {
				t.Fatal(err)
			}
			s.clear(t.Context())
			unsubscribe()
			want := []Event{{Kind: "add", ID: 1, Entry: first}, {Kind: "add", ID: 2, Entry: second}, {Kind: "refresh"}}
			if diff := gocmp.Diff(want, observed); diff != "" {
				t.Fatal(diff)
			}
			var got []Event
			for e := range queued {
				got = append(got, e)
			}
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Fatal(diff)
			}
			cancel()
			cancel()
			if err := s.AddLog(t.Context(), first); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(want, observed); diff != "" {
				t.Fatal(diff)
			}
			s.Observe(func(e Event) { observed = append(observed, e) })
			if err := s.Done(t.Context()); err != nil {
				t.Fatal(err)
			}
			s.clear(t.Context())
			if diff := gocmp.Diff(want, observed); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
