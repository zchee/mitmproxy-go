// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

// ErrNoView indicates that no registered view has a working render priority.
var ErrNoView = errors.New("at least one view needs to have a working render priority")

// Registry holds named views in registration order. Its zero value is empty.
// Operations are concurrency-safe; view and subscriber calls run without its lock.
type Registry struct {
	mu          sync.RWMutex
	views       []View
	subscribers []subscription
	nextID      uint64
}

type subscription struct {
	id     uint64
	notify func(View)
}

// NewRegistry returns a registry containing the built-in views.
func NewRegistry() *Registry {
	r := &Registry{}
	r.Register(Raw{})
	r.Register(HexDump{})
	r.Register(HexStream{})
	r.Register(JSON{})
	r.Register(XMLHTML{})
	r.Register(URLEncoded{})
	r.Register(Query{})
	r.Register(Multipart{})
	r.Register(Image{})
	return r
}

// DefaultRegistry is used by PrettifyMessage when no registry is specified.
var DefaultRegistry = NewRegistry()

// Register adds or replaces a view, retaining its position when replaced.
// It panics for a nil view or an empty name.
func (r *Registry) Register(view View) {
	if view == nil || view.Name() == "" {
		panic("contentviews: a view needs a name")
	}
	name := strings.ToLower(view.Name())
	r.mu.Lock()
	replaced := false
	for i, v := range r.views {
		if strings.ToLower(v.Name()) == name {
			r.views[i] = view
			replaced = true
			break
		}
	}
	if !replaced {
		r.views = append(r.views, view)
	}
	subscribers := slices.Clone(r.subscribers)
	r.mu.Unlock()
	if replaced {
		logSink().Info(fmt.Sprintf("Replacing existing %s contentview.", name))
	}
	for _, s := range subscribers {
		s.notify(view)
	}
}

// Subscribe registers an upstream on_change notification and returns an idempotent unsubscribe.
// Notifications are synchronous and may call back into the registry.
func (r *Registry) Subscribe(notify func(View)) func() {
	r.mu.Lock()
	r.nextID++
	id := r.nextID
	r.subscribers = append(r.subscribers, subscription{id, notify})
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		r.subscribers = slices.DeleteFunc(r.subscribers, func(s subscription) bool { return s.id == id })
		r.mu.Unlock()
	}
}

// Get looks up a name case-insensitively.
func (r *Registry) Get(name string) (View, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, v := range r.views {
		if strings.EqualFold(v.Name(), name) {
			return v, true
		}
	}
	return nil, false
}

// AvailableViews lists auto followed by the sorted lower-case view names.
func (r *Registry) AvailableViews() []string {
	r.mu.RLock()
	names := make([]string, 0, len(r.views)+1)
	for _, v := range r.views {
		names = append(names, strings.ToLower(v.Name()))
	}
	r.mu.RUnlock()
	slices.Sort(names)
	return append([]string{"auto"}, names...)
}

// GetView selects name or, for auto, an empty name, or an unknown name, the
// highest-priority view. Ties retain registration order. Panicking priority
// implementations are logged and skipped. ErrNoView means none succeeded.
func (r *Registry) GetView(data []byte, metadata Metadata, name string) (View, error) {
	if name != "" && name != "auto" {
		if v, ok := r.Get(name); ok {
			return v, nil
		}
		logSink().Warn(fmt.Sprintf("Unknown contentview %s, selecting best match instead.", pyrepr.Str(name)))
	}
	r.mu.RLock()
	views := slices.Clone(r.views)
	r.mu.RUnlock()
	var best View
	var highest float64
	for _, v := range views {
		priority, ok := renderPriority(v, data, metadata)
		if ok && (best == nil || priority > highest) {
			best, highest = v, priority
		}
	}
	if best == nil {
		return nil, ErrNoView
	}
	return best, nil
}

func renderPriority(v View, data []byte, metadata Metadata) (priority float64, ok bool) {
	defer func() {
		if err := recover(); err != nil {
			logSink().Error("Error in "+v.Name()+".render_priority", "error", err)
		}
	}()
	return v.RenderPriority(data, metadata), true
}
