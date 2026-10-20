// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package view

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
)

func TestViewObserverOwnership(t *testing.T) {
	tests := map[string]struct{}{"detached copies preserve identity and isolate mutations": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			v := New(nil)
			stored := fixture("GET", 1)
			stored.Common().Live = true
			var retained *flow.HTTPFlow
			v.Observe(func(event Event) {
				if event.Kind != "view_add" {
					return
				}
				retained = event.Flow.(*flow.HTTPFlow)
				if retained == stored || retained.Common().ID != stored.Common().ID || !retained.Common().Live {
					t.Fatal("copy changed flow identity/live state or retained the store pointer")
				}
				retained.Request.Method = "CALLBACK"
				retained.Common().Live = false
			})
			v.Observe(func(event Event) {
				if event.Kind != "view_add" {
					return
				}
				if diff := gocmp.Diff("GET", event.Flow.(*flow.HTTPFlow).Request.Method); diff != "" {
					t.Fatal("another observer changed this snapshot: " + diff)
				}
			})
			channel, unsubscribe := v.Subscribe(8)
			v.Add(t.Context(), []flow.Flow{stored})
			unsubscribe()
			for event := range channel {
				if event.Flow != nil && event.Flow != stored {
					t.Fatal("bounded subscription no longer carries the existing dispatch-owned flow")
				}
			}
			if retained == nil || stored.Request.Method != "GET" || !stored.Common().Live {
				t.Fatal("observer mutation changed the stored flow")
			}
			stored.Request.Method = "POST"
			if err := v.Update(t.Context(), []flow.Flow{stored}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff("CALLBACK", retained.Request.Method); diff != "" {
				t.Fatal("later store mutation changed a retained copy: " + diff)
			}
		})
	}
}

func TestViewObserverUnsubscribeDuringCallback(t *testing.T) {
	tests := map[string]struct{}{"self and another callback finish the captured emission": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			v := New(nil)
			var first, second int
			var stopFirst, stopSecond func()
			stopFirst = v.Observe(func(event Event) {
				if event.Kind != "view_add" {
					return
				}
				first++
				stopFirst()
				stopSecond()
				stopFirst()
				stopSecond()
			})
			stopSecond = v.Observe(func(event Event) {
				if event.Kind == "view_add" {
					second++
				}
			})
			v.Add(t.Context(), []flow.Flow{fixture("GET", 1)})
			if first != 1 || second != 1 {
				t.Fatalf("captured callbacks = %d, %d", first, second)
			}
			v.Add(t.Context(), []flow.Flow{fixture("POST", 2)})
			if first != 1 || second != 1 {
				t.Fatalf("unsubscribed callbacks ran: %d, %d", first, second)
			}
			stopFirst()
			stopSecond()
		})
	}
}
