// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package view

import (
	json "encoding/json/v2"
	"slices"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/flow"
)

func TestViewObservers(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"event snapshots precede later mutation": {run: func(t *testing.T) {
			v := New(nil)
			f := fixture("GET", 1)
			type snapshot struct {
				Kind     string
				Method   string
				Matching bool
			}
			expr, err := filter.Parse("~m GET")
			if err != nil {
				t.Fatal(err)
			}
			var captured [][]byte
			cancel := v.Observe(func(e Event) {
				if e.Kind != "view_add" && e.Kind != "view_update" && e.Kind != "view_remove" {
					return
				}
				b, err := json.Marshal(snapshot{e.Kind, e.Flow.(*flow.HTTPFlow).Request.Method, filter.Match(expr, e.Flow)})
				if err != nil {
					t.Fatal(err)
				}
				captured = append(captured, b)
			})
			defer cancel()
			v.Add(t.Context(), []flow.Flow{f})
			f.Request.Method = "POST"
			if err := v.Update(t.Context(), []flow.Flow{f}); err != nil {
				t.Fatal(err)
			}
			if err := v.remove(t.Context(), []flow.Flow{f}); err != nil {
				t.Fatal(err)
			}
			f.Request.Method = "DELETE"
			var got []snapshot
			for _, b := range captured {
				var s snapshot
				if err := json.Unmarshal(b, &s); err != nil {
					t.Fatal(err)
				}
				got = append(got, s)
			}
			want := []snapshot{{"view_add", "GET", true}, {"view_update", "POST", false}, {"view_remove", "POST", false}}
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Fatal(diff)
			}
		}},
		"lifetime and instance isolation": {run: func(t *testing.T) {
			v, other := New(nil), New(nil)
			var kinds []string
			cancel := v.Observe(func(e Event) { kinds = append(kinds, e.Kind) })
			v.Observe(nil)()
			other.Add(t.Context(), []flow.Flow{fixture("GET", 1)})
			if len(kinds) != 0 {
				t.Fatal("observer leaked across instances")
			}
			v.Add(t.Context(), []flow.Flow{fixture("GET", 1)})
			want := []string{"store_add", "focus", "view_add"}
			if diff := gocmp.Diff(want, kinds); diff != "" {
				t.Fatal(diff)
			}
			cancel()
			cancel()
			v.Add(t.Context(), []flow.Flow{fixture("POST", 2)})
			if diff := gocmp.Diff(want, kinds); diff != "" {
				t.Fatal(diff)
			}
			v.Observe(func(e Event) { kinds = append(kinds, e.Kind) })
			if err := v.Done(t.Context()); err != nil {
				t.Fatal(err)
			}
			v.clear(t.Context())
			if diff := gocmp.Diff(want, kinds); diff != "" {
				t.Fatal(diff)
			}
		}},
		"bounded subscribers retain existing sequence": {run: func(t *testing.T) {
			v := New(nil)
			var observed []string
			cancel := v.Observe(func(e Event) { observed = append(observed, e.Kind) })
			defer cancel()
			events, unsubscribe := v.Subscribe(32)
			v.Add(t.Context(), []flow.Flow{fixture("GET", 1)})
			v.clear(t.Context())
			unsubscribe()
			var queued []string
			for e := range events {
				queued = append(queued, e.Kind)
			}
			if diff := gocmp.Diff(observed, queued); diff != "" {
				t.Fatal(diff)
			}
			before := slices.Clone(observed)
			v.Observe(func(Event) {})()
			if diff := gocmp.Diff(before, observed); diff != "" {
				t.Fatal(diff)
			}
		}},
	}
	for name, tt := range tests {
		t.Run(name, tt.run)
	}
}
