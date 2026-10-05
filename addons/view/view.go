// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package view maintains an ordered, filtered flow store and frontend focus.
// All access, including subscriptions and snapshots, must run inside hooks,
// commands or master.Do; the addon dispatch lock serializes its state.
package view

import (
	"context"
	"errors"
	"slices"

	"github.com/google/btree"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/omap"
)

// Event describes a view, store or focus change. Kind is view_add, view_remove,
// view_update, view_refresh, store_add, store_remove, store_refresh or focus.
// Index is the ascending index before removal, matching upstream's signal.
// Flow is nil for refresh and focus events. Flow objects remain dispatch-owned;
// a consumer must use master.Do before inspecting them.
type Event struct {
	Kind  string
	Flow  flow.Flow
	Index int
}

type orderValue struct {
	number float64
	text   string
}
type item struct {
	key      orderValue
	sequence uint64
	f        flow.Flow
}

// View stores flows in insertion order and exposes a separately ordered view.
// Construct it with New; the zero value is not usable.
type View struct {
	// Focus tracks the selected flow.
	Focus *Focus
	// Settings holds transient per-flow frontend values.
	Settings       *Settings
	manager        *addon.Manager
	store          *omap.Map[flow.Flow]
	tree           *btree.BTreeG[item]
	visible        map[string]item
	keys           map[string]map[string]orderValue
	order          string
	reversed       bool
	marked         bool
	follow         bool
	expression     filter.Expr
	sequence       uint64
	subscribers    map[uint64]chan Event
	nextSubscriber uint64
}

// New constructs a View. A nil manager permits standalone store use; commands
// that notify other addons require a manager.
func New(manager *addon.Manager) *View {
	v := &View{manager: manager, store: omap.New[flow.Flow](), visible: make(map[string]item), keys: make(map[string]map[string]orderValue), subscribers: make(map[uint64]chan Event)}
	v.tree = btree.NewG(32, less)
	v.Focus = &Focus{view: v}
	v.Settings = &Settings{view: v, values: make(map[string]map[string]string)}
	return v
}

func less(a, b item) bool {
	if a.key.number != b.key.number {
		return a.key.number < b.key.number
	}
	if a.key.text != b.key.text {
		return a.key.text < b.key.text
	}
	return a.sequence < b.sequence
}

// Subscribe returns a bounded event channel and cancellation function. The
// capacity is at least one. Sends never block: overflow closes and removes that
// subscriber, leaving queued events readable. The consumer must resnapshot
// after closure. Subscribe and cancel, like all View access, require the dispatch
// lock. No goroutine is started and consumers must not wait under that lock.
func (v *View) Subscribe(capacity int) (<-chan Event, func()) {
	v.nextSubscriber++
	id := v.nextSubscriber
	ch := make(chan Event, max(capacity, 1))
	v.subscribers[id] = ch
	return ch, func() {
		if existing, ok := v.subscribers[id]; ok {
			delete(v.subscribers, id)
			close(existing)
		}
	}
}

func (v *View) emit(e Event) {
	switch e.Kind {
	case "view_add":
		if v.Focus.selected == nil {
			_ = v.Focus.Set(e.Flow)
		}
	case "view_remove":
		if v.Len() == 0 {
			_ = v.Focus.Set(nil)
		} else if e.Flow == v.Focus.selected {
			_ = v.Focus.SetIndex(min(e.Index, v.Len()-1))
		}
	case "view_refresh":
		if v.Len() == 0 {
			_ = v.Focus.Set(nil)
		} else if v.Focus.selected == nil {
			_ = v.Focus.SetIndex(0)
		} else if !v.Contains(v.Focus.selected) {
			idx := min(v.bisect(v.Focus.selected), v.Len()-1)
			_ = v.Focus.SetIndex(idx)
		}
	case "store_remove":
		delete(v.Settings.values, e.Flow.Common().ID)
		delete(v.keys, e.Flow.Common().ID)
	case "store_refresh":
		for id := range v.Settings.values {
			if !v.store.Has(id) {
				delete(v.Settings.values, id)
			}
		}
		for id := range v.keys {
			if !v.store.Has(id) {
				delete(v.keys, id)
			}
		}
	}
	for id, ch := range v.subscribers {
		select {
		case ch <- e:
		default:
			close(ch)
			delete(v.subscribers, id)
		}
	}
}

// Len returns the number of visible flows.
func (v *View) Len() int { return v.tree.Len() }

// StoreCount returns the number of stored flows, including hidden flows.
func (v *View) StoreCount() int { return v.store.Len() }

// GetByID returns the stored flow, or nil when the ID is absent.
func (v *View) GetByID(id string) flow.Flow { f, _ := v.store.Get(id); return f }

// Contains reports whether the flow is visible.
func (v *View) Contains(f flow.Flow) bool {
	if f == nil {
		return false
	}
	entry, ok := v.visible[f.Common().ID]
	return ok && entry.f == f
}

// Flows returns a snapshot of visible flows in display order.
func (v *View) Flows() []flow.Flow {
	fs := make([]flow.Flow, 0, v.Len())
	appendFlow := func(i item) bool { fs = append(fs, i.f); return true }
	if v.reversed {
		v.tree.Descend(appendFlow)
	} else {
		v.tree.Ascend(appendFlow)
	}
	return fs
}

// At returns a visible flow by index. Negative indices count from the end.
func (v *View) At(index int) (flow.Flow, error) {
	if index < 0 {
		index += v.Len()
	}
	if index < 0 || index >= v.Len() {
		return nil, errors.New("Index out of view bounds")
	}
	var f flow.Flow
	visit := func(i item) bool {
		if index == 0 {
			f = i.f
			return false
		}
		index--
		return true
	}
	if v.reversed {
		v.tree.Descend(visit)
	} else {
		v.tree.Ascend(visit)
	}
	return f, nil
}

// Index returns a visible flow's display index, or -1 when it is absent.
func (v *View) Index(f flow.Flow) int {
	if !v.Contains(f) {
		return -1
	}
	index := 0
	v.tree.Ascend(func(i item) bool {
		if i.f == f {
			return false
		}
		index++
		return true
	})
	if v.reversed {
		return v.Len() - index - 1
	}
	return index
}

func (v *View) cachedKey(f flow.Flow) orderValue {
	id := f.Common().ID
	cache := v.keys[id]
	if cache == nil {
		cache = make(map[string]orderValue)
		v.keys[id] = cache
	}
	if key, ok := cache[v.order]; ok {
		return key
	}
	key := generate(v.order, f)
	cache[v.order] = key
	return key
}

func (v *View) insert(f flow.Flow) {
	v.sequence++
	entry := item{key: v.cachedKey(f), sequence: v.sequence, f: f}
	v.visible[f.Common().ID] = entry
	v.tree.ReplaceOrInsert(entry)
}

func (v *View) erase(f flow.Flow) {
	id := f.Common().ID
	v.tree.Delete(v.visible[id])
	delete(v.visible, id)
}

func (v *View) refilter() {
	v.tree.Clear(false)
	clear(v.visible)
	for _, f := range v.store.All() {
		if (!v.marked || f.Common().Marked != "") && filter.Match(v.expression, f) {
			v.insert(f)
		}
	}
	v.emit(Event{Kind: "view_refresh"})
}

func (v *View) bisect(f flow.Flow) int {
	key := generate(v.order, f)
	if cache := v.keys[f.Common().ID]; cache != nil {
		if cached, ok := cache[v.order]; ok {
			key = cached
		}
	}
	n := 0
	v.tree.Ascend(func(i item) bool {
		if less(item{key: key, sequence: ^uint64(0)}, i) {
			return false
		}
		n++
		return true
	})
	// Upstream reverses the position immediately before the insertion point.
	if v.reversed {
		if n == 0 {
			return 1
		}
		return v.Len() - n + 1
	}
	return n
}

// Add stores previously unseen flows and adds those matching the filter to the
// view. Like upstream, marked-only mode affects refiltering, not this path.
func (v *View) Add(_ context.Context, flows []flow.Flow) {
	for _, f := range flows {
		if v.store.Has(f.Common().ID) {
			continue
		}
		v.store.Set(f.Common().ID, f)
		v.emit(Event{Kind: "store_add", Flow: f})
		if filter.Match(v.expression, f) {
			v.insert(f)
			if v.follow {
				_ = v.Focus.Set(f)
			}
			v.emit(Event{Kind: "view_add", Flow: f})
		}
	}
}

// Update refreshes the order and visibility of stored flows; unknown flows are ignored.
func (v *View) Update(_ context.Context, flows []flow.Flow) error {
	for _, f := range flows {
		if !v.store.Has(f.Common().ID) {
			continue
		}
		if filter.Match(v.expression, f) {
			if !v.Contains(f) {
				v.insert(f)
				if v.follow {
					_ = v.Focus.Set(f)
				}
				v.emit(Event{Kind: "view_add", Flow: f})
				continue
			}
			entry := v.visible[f.Common().ID]
			key := generate(v.order, f)
			if key != entry.key {
				v.erase(f)
				v.keys[f.Common().ID][v.order] = key
				v.insert(f)
				v.emit(Event{Kind: "view_refresh"})
			}
			v.emit(Event{Kind: "view_update", Flow: f})
		} else if v.Contains(f) {
			index := v.Index(f)
			if v.reversed {
				index = v.Len() - index - 1
			}
			v.erase(f)
			v.emit(Event{Kind: "view_remove", Flow: f, Index: index})
		}
	}
	return nil
}

// SetFilter replaces the filter and rebuilds the visible view. Nil matches all flows.
func (v *View) SetFilter(expression filter.Expr) { v.expression = expression; v.refilter() }

// Focus tracks one selected visible flow. Its methods require the dispatch lock.
type Focus struct {
	view     *View
	selected flow.Flow
}

// Flow returns the selected flow, or nil for an empty view.
func (f *Focus) Flow() flow.Flow { return f.selected }

// Index returns the selection's display index, or -1 without a selection.
func (f *Focus) Index() int { return f.view.Index(f.selected) }

// Set selects a visible flow or clears the selection with nil.
func (f *Focus) Set(selected flow.Flow) error {
	if selected != nil && !f.view.Contains(selected) {
		return errors.New("Attempt to set focus to flow not in view") //nolint:staticcheck // Preserve upstream's user-facing error text.
	}
	f.selected = selected
	f.view.emit(Event{Kind: "focus"})
	return nil
}

// SetIndex selects a flow at a nonnegative display index.
func (f *Focus) SetIndex(index int) error {
	if index < 0 {
		return errors.New("Index out of view bounds")
	}
	selected, err := f.view.At(index)
	if err != nil {
		return err
	}
	return f.Set(selected)
}

// Settings holds transient string settings that expire when a flow is removed.
type Settings struct {
	view   *View
	values map[string]map[string]string
}

// Values returns the flow's mutable settings, or an error for an unknown flow.
// The returned map may only be used while the dispatch lock is held.
func (s *Settings) Values(f flow.Flow) (map[string]string, error) {
	id := f.Common().ID
	if !s.view.store.Has(id) {
		return nil, errors.New("Flow not in store")
	}
	if s.values[id] == nil {
		s.values[id] = make(map[string]string)
	}
	return s.values[id], nil
}

// IDs returns the IDs with settings in unspecified order.
func (s *Settings) IDs() []string {
	ids := make([]string, 0, len(s.values))
	for id := range s.values {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}
