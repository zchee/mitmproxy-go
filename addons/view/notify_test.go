// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package view

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
)

type copyCountingFlow struct {
	flow.Flow
	copies int
}

func (f *copyCountingFlow) Copy() flow.Flow {
	f.copies++
	return f.Flow.Copy()
}

func TestViewNotify(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"all emissions match payload observers": {run: func(t *testing.T) {
			v := New(nil)
			var observed, notified []string
			v.Observe(func(e Event) { observed = append(observed, e.Kind) })
			v.Notify(func() { notified = append(notified, observed[len(observed)-1]) })
			f := fixture("GET", 1)
			v.Add(t.Context(), []flow.Flow{f})
			if err := v.Update(t.Context(), []flow.Flow{f}); err != nil {
				t.Fatal(err)
			}
			v.SetFilter(nil)
			if err := v.Focus.Set(f); err != nil {
				t.Fatal(err)
			}
			if err := v.remove(t.Context(), []flow.Flow{f}); err != nil {
				t.Fatal(err)
			}
			v.clear(t.Context())
			want := []string{"store_add", "focus", "view_add", "view_update", "view_refresh", "focus", "focus", "view_remove", "store_remove", "focus", "view_refresh", "store_refresh"}
			if diff := gocmp.Diff(want, observed); diff != "" {
				t.Fatalf("payload event sequence (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(observed, notified); diff != "" {
				t.Fatalf("notification event sequence (-want +got):\n%s", diff)
			}
		}},
		"no flow copy without a payload observer": {run: func(t *testing.T) {
			v := New(nil)
			f := &copyCountingFlow{Flow: fixture("GET", 1)}
			calls := 0
			v.Notify(func() { calls++ })
			v.emit(Event{Kind: "view_update", Flow: f})
			if diff := gocmp.Diff([2]int{1, 0}, [2]int{calls, f.copies}); diff != "" {
				t.Fatalf("notification calls and flow copies (-want +got):\n%s", diff)
			}
		}},
		"payload observers retain independent copies": {run: func(t *testing.T) {
			v := New(nil)
			source := fixture("GET", 1)
			f := &copyCountingFlow{Flow: source}
			calls := 0
			v.Notify(func() { calls++ })
			var snapshots []flow.Flow
			for range 2 {
				v.Observe(func(e Event) { snapshots = append(snapshots, e.Flow) })
			}
			v.emit(Event{Kind: "view_update", Flow: f})
			if diff := gocmp.Diff([2]int{1, 2}, [2]int{calls, f.copies}); diff != "" {
				t.Fatalf("notification calls and payload copies (-want +got):\n%s", diff)
			}
			snapshots[0].(*flow.HTTPFlow).Request.Method = "POST"
			if diff := gocmp.Diff("GET", snapshots[1].(*flow.HTTPFlow).Request.Method); diff != "" {
				t.Fatalf("other observer was mutated (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff("GET", source.Request.Method); diff != "" {
				t.Fatalf("store flow was mutated (-want +got):\n%s", diff)
			}
			for _, snapshot := range snapshots {
				if snapshot == f || snapshot == source {
					t.Fatal("payload observer retained the source flow")
				}
				if diff := gocmp.Diff(source.Common().ID, snapshot.Common().ID); diff != "" {
					t.Fatal(diff)
				}
			}
		}},
		"nil unsubscribe done and instance isolation": {run: func(t *testing.T) {
			v, other := New(nil), New(nil)
			v.Notify(nil)()
			if len(v.notifiers) != 0 {
				t.Fatal("nil callback was registered")
			}
			calls := 0
			cancel := v.Notify(func() { calls++ })
			other.Add(t.Context(), []flow.Flow{fixture("GET", 1)})
			v.emit(Event{Kind: "focus"})
			cancel()
			cancel()
			v.emit(Event{Kind: "focus"})
			v.Notify(func() { calls++ })
			if err := v.Done(t.Context()); err != nil {
				t.Fatal(err)
			}
			v.emit(Event{Kind: "focus"})
			cancel()
			if diff := gocmp.Diff(1, calls); diff != "" {
				t.Fatalf("calls after unsubscribe and Done (-want +got):\n%s", diff)
			}
			if len(v.notifiers) != 0 {
				t.Fatal("Done retained callbacks")
			}
		}},
	}
	for name, tt := range tests {
		t.Run(name, tt.run)
	}
}
