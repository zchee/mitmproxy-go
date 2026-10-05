// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package eventstore keeps a bounded frontend event log. All methods must run
// under the addon dispatch lock, in hooks, commands or master.Do callbacks.
package eventstore

import (
	"context"
	"errors"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
)

// Event describes an added log entry or a refresh after clearing the store.
// Kind is "add" or "refresh"; Entry is meaningful only for "add".
type Event struct {
	Kind  string
	Entry addon.LogEntry
}

// EventStore retains the most recent log entries in a ring. Construct it with New.
type EventStore struct {
	size           int
	data           []addon.LogEntry
	start          int
	subscribers    map[uint64]chan Event
	nextSubscriber uint64
}

// New constructs an EventStore with capacity 10000 by default. An optional size
// sets the capacity, including zero to discard stored entries but still signal
// additions. Negative sizes and more than one size argument return an error.
// Logging is supplied by the master's existing add_log dispatch, not a global
// handler installed by this constructor.
func New(size ...int) (*EventStore, error) {
	capacity := 10000
	if len(size) > 1 {
		return nil, errors.New("eventstore: at most one size is allowed")
	}
	if len(size) == 1 {
		capacity = size[0]
	}
	if capacity < 0 {
		return nil, errors.New("maxlen must be non-negative")
	}
	return &EventStore{size: capacity, subscribers: make(map[uint64]chan Event)}, nil
}

// Load registers the eventstore.clear command. The addon has no options.
func (s *EventStore) Load(_ context.Context, loader *addon.Loader) error {
	return loader.AddCommand("eventstore.clear", s.clear, command.WithHelp("Clear the event log."))
}

// Size returns the maximum number of retained entries.
func (s *EventStore) Size() int { return s.size }

// Entries returns a snapshot of entries from oldest to newest.
func (s *EventStore) Entries() []addon.LogEntry {
	entries := make([]addon.LogEntry, 0, len(s.data))
	entries = append(entries, s.data[s.start:]...)
	return append(entries, s.data[:s.start]...)
}

// AddLog retains an entry and emits an addition event under the dispatch lock.
func (s *EventStore) AddLog(_ context.Context, entry addon.LogEntry) error {
	if s.size > 0 {
		if len(s.data) < s.size {
			s.data = append(s.data, entry)
		} else {
			s.data[s.start] = entry
			s.start = (s.start + 1) % s.size
		}
	}
	s.emit(Event{Kind: "add", Entry: entry})
	return nil
}

func (s *EventStore) clear(context.Context) {
	clear(s.data)
	s.data = s.data[:0]
	s.start = 0
	s.emit(Event{Kind: "refresh"})
}

// Subscribe returns a channel bounded by max(capacity, 1) and its cancellation
// function. Neither operation may run outside the dispatch lock. Sends never
// block: overflow closes and removes that subscriber, leaving queued events
// readable. The consumer must resnapshot on closure. No goroutine is started.
func (s *EventStore) Subscribe(capacity int) (<-chan Event, func()) {
	s.nextSubscriber++
	id := s.nextSubscriber
	ch := make(chan Event, max(capacity, 1))
	s.subscribers[id] = ch
	return ch, func() {
		if existing, ok := s.subscribers[id]; ok {
			delete(s.subscribers, id)
			close(existing)
		}
	}
}

func (s *EventStore) emit(event Event) {
	for id, ch := range s.subscribers {
		select {
		case ch <- event:
		default:
			close(ch)
			delete(s.subscribers, id)
		}
	}
}

// Done releases every subscription; existing entries remain accessible.
func (s *EventStore) Done(context.Context) error {
	for id, ch := range s.subscribers {
		close(ch)
		delete(s.subscribers, id)
	}
	return nil
}
