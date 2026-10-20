// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package eventstore

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
)

func TestEventRecords(t *testing.T) {
	tests := map[string]struct{ capacity int }{
		"zero retention":    {capacity: 0},
		"single entry ring": {capacity: 1},
		"wrapped ring":      {capacity: 2},
		"partial retention": {capacity: 4},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			store, err := New(tt.capacity)
			if err != nil {
				t.Fatal(err)
			}
			var events []Event
			store.Observe(func(event Event) { events = append(events, event) })
			all := make([]Record, 0, 5)
			for index := range 5 {
				entry := addon.LogEntry{Msg: string(rune('a' + index))}
				if err := store.Add(t.Context(), entry); err != nil {
					t.Fatal(err)
				}
				all = append(all, Record{ID: uint64(index + 1), Entry: entry})
				if diff := gocmp.Diff(Event{Kind: "add", ID: uint64(index + 1), Entry: entry}, events[index]); diff != "" {
					t.Fatal(diff)
				}
			}
			want := append(make([]Record, 0), all[len(all)-tt.capacity:]...)
			if diff := gocmp.Diff(want, store.Records()); diff != "" {
				t.Fatal(diff)
			}
			entries := make([]addon.LogEntry, 0, len(want))
			for _, record := range want {
				entries = append(entries, record.Entry)
			}
			if diff := gocmp.Diff(entries, store.Entries()); diff != "" {
				t.Fatal(diff)
			}
			retained := store.Records()
			if len(retained) != 0 {
				retained[0].ID = 999
				retained[0].Entry.Msg = "changed"
			}
			if diff := gocmp.Diff(want, store.Records()); diff != "" {
				t.Fatal("record snapshot aliases store: " + diff)
			}
			store.clear(t.Context())
			if len(store.Records()) != 0 {
				t.Fatal("clear retained records")
			}
			if err := store.Add(t.Context(), addon.LogEntry{Msg: "after clear"}); err != nil {
				t.Fatal(err)
			}
			if got := events[len(events)-1].ID; got != 6 {
				t.Fatalf("identity after clear = %d, want 6", got)
			}
			if records := store.Records(); tt.capacity > 0 && (len(records) != 1 || records[0].ID != 6) {
				t.Fatal("retained identity differs from emitted identity")
			}
			other, err := New()
			if err != nil {
				t.Fatal(err)
			}
			if err := other.Add(t.Context(), addon.LogEntry{}); err != nil {
				t.Fatal(err)
			}
			if got := other.Records()[0].ID; got != 1 {
				t.Fatalf("store identity is not independent: %d", got)
			}
		})
	}
}

func TestEventIdentityExhaustion(t *testing.T) {
	tests := map[string]struct{}{"never wrap or emit an unretained identity": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			store, err := New(1)
			if err != nil {
				t.Fatal(err)
			}
			store.nextID = ^uint64(0) - 1
			var events []Event
			store.Observe(func(event Event) { events = append(events, event) })
			if err := store.Add(t.Context(), addon.LogEntry{Msg: "last identity"}); err != nil {
				t.Fatal(err)
			}
			before := store.Records()
			if before[0].ID != ^uint64(0) {
				t.Fatal("last uint64 identity was not assigned")
			}
			if err := store.Add(t.Context(), addon.LogEntry{Msg: "must not replace"}); err == nil {
				t.Fatal("exhausted identity counter wrapped")
			}
			if diff := gocmp.Diff(before, store.Records()); diff != "" {
				t.Fatal(diff)
			}
			if len(events) != 1 {
				t.Fatal("exhaustion emitted an addition")
			}
		})
	}
}

func TestEventObserverUnsubscribeDuringCallback(t *testing.T) {
	tests := map[string]struct{}{"captured callbacks finish while unsubscription affects the next event": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			store, err := New()
			if err != nil {
				t.Fatal(err)
			}
			var first, second int
			var stopFirst, stopSecond func()
			stopFirst = store.Observe(func(Event) { first++; stopFirst(); stopSecond(); stopFirst(); stopSecond() })
			stopSecond = store.Observe(func(Event) { second++ })
			if err := store.Add(t.Context(), addon.LogEntry{Msg: "first"}); err != nil {
				t.Fatal(err)
			}
			if first != 1 || second != 1 {
				t.Fatalf("captured callbacks = %d, %d", first, second)
			}
			if err := store.Add(t.Context(), addon.LogEntry{Msg: "second"}); err != nil {
				t.Fatal(err)
			}
			if first != 1 || second != 1 {
				t.Fatalf("unsubscribed callbacks ran: %d, %d", first, second)
			}
			stopFirst()
			stopSecond()
		})
	}
}
