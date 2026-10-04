// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package options is a port of mitmproxy's option manager
// (mitmproxy/optmanager.py) and its core option set (mitmproxy/options.py).
//
// A [Manager] holds a registry of typed options. Values are read with the
// typed getters ([Manager.Bool], [Manager.Int], [Manager.Str],
// [Manager.OptStr], [Manager.OptInt], [Manager.Seq] or [Get]) and changed
// with [Manager.Update], [Manager.Set] or by loading YAML configuration.
// Every change is announced to the callbacks registered with
// [Manager.Subscribe]; a callback that returns an [*OptionsError] rolls the
// whole change back.
//
// Every method that announces a change takes a [context.Context] and hands
// it to the subscribers unchanged; the package itself never inspects it. A
// caller that changes options from inside a hook passes the context of that
// hook, so that subscribers which dispatch further hooks (such as the
// configure hook) can tell that they run inside the caller's dispatch.
package options

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/zchee/mitmproxy-go/internal/omap"
)

// option is one registered option.
type option struct {
	name    string
	typ     Type
	def     any
	value   any
	isSet   bool
	help    string
	choices []string
}

func (o *option) current() any {
	if o.isSet {
		return o.value
	}
	return o.def
}

func (o *option) snapshot() Option {
	return Option{
		name:    o.name,
		typ:     o.typ,
		def:     copyValue(o.def),
		current: copyValue(o.current()),
		help:    o.help,
		choices: slices.Clone(o.choices),
	}
}

// Option is a point-in-time copy of a registered option.
type Option struct {
	name    string
	typ     Type
	def     any
	current any
	help    string
	choices []string
}

// Name returns the option name.
func (o Option) Name() string { return o.name }

// Type returns the option type.
func (o Option) Type() Type { return o.typ }

// Default returns a copy of the default value.
func (o Option) Default() any { return copyValue(o.def) }

// Current returns a copy of the value the option had when the snapshot was
// taken.
func (o Option) Current() any { return copyValue(o.current) }

// Help returns the help text, normalised the way mitmproxy normalises it:
// dedented, stripped, with newlines replaced by spaces.
func (o Option) Help() string { return o.help }

// Choices returns the valid values, or nil when the option accepts any value
// of its type.
func (o Option) Choices() []string { return slices.Clone(o.choices) }

// HasChanged reports whether the value differed from the default when the
// snapshot was taken.
func (o Option) HasChanged() bool { return !equalValues(o.current, o.def) }

// AddOption configures an option registered with [Manager.Add].
type AddOption func(*option)

// WithChoices restricts the option to the listed values.
//
// As in mitmproxy, choices are informational: they appear in dumps, help
// output and command-line validation, but [Manager.Update] and [Manager.Set]
// do not enforce them.
func WithChoices(choices ...string) AddOption {
	return func(o *option) { o.choices = slices.Clone(choices) }
}

type subscriber struct {
	id uint64
	fn func(ctx context.Context, updated map[string]struct{}) error
}

type errorSubscriber struct {
	id uint64
	fn func(error)
}

// Manager is a registry of typed options. It is safe for concurrent use.
//
// Subscribers run on the goroutine that made the change, with the context
// that change was made with, after the change has been applied and without
// any Manager lock held, so a subscriber may read options and may itself
// call [Manager.Update].
type Manager struct {
	mu       sync.Mutex
	opts     *omap.Map[*option]
	deferred *omap.Map[any]
	subs     []subscriber
	errSubs  []errorSubscriber
	nextID   uint64
}

// NewManager returns a Manager with no options registered.
func NewManager() *Manager {
	return &Manager{
		opts:     omap.New[*option](),
		deferred: omap.New[any](),
	}
}

// Add registers an option, replacing any option of the same name, and
// announces the new option to subscribers.
//
// help is normalised as mitmproxy does: dedented, stripped, and with
// newlines replaced by spaces. Add returns a [*TypeError] when def does not
// fit typ, and otherwise the error a subscriber returned, if any. An error
// from a subscriber does not unregister the option.
func (m *Manager) Add(ctx context.Context, name string, typ Type, def any, help string, opts ...AddOption) error {
	cdef, err := coerce(name, typ, def)
	if err != nil {
		return err
	}
	o := &option{
		name: name,
		typ:  typ,
		def:  cdef,
		help: strings.ReplaceAll(strings.TrimSpace(dedent(help)), "\n", " "),
	}
	for _, opt := range opts {
		opt(o)
	}
	m.mu.Lock()
	m.opts.Set(name, o)
	m.mu.Unlock()
	return m.notify(ctx, map[string]struct{}{name: {}})
}

// Subscribe registers fn to be called after every change with the context
// passed to the method that made the change and the set of option names
// that changed (mitmproxy's OptManager.changed signal).
// Subscribers run in registration order; the first one to return an error
// stops the chain.
//
// If fn returns an [*OptionsError], the change is rolled back, the error
// subscribers registered with [Manager.OnError] are notified, every
// subscriber is called again with the same context and names, and the error
// is returned to the caller that made the change. The returned function
// removes the subscription.
func (m *Manager) Subscribe(fn func(ctx context.Context, updated map[string]struct{}) error) (cancel func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	id := m.nextID
	m.subs = append(m.subs, subscriber{id: id, fn: fn})
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.subs = slices.DeleteFunc(m.subs, func(s subscriber) bool { return s.id == id })
	}
}

// OnError registers fn to be called with the [*OptionsError] that caused a
// rollback (mitmproxy's OptManager.errored signal), before the rollback is
// applied. The returned function removes the registration.
func (m *Manager) OnError(fn func(error)) (cancel func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	id := m.nextID
	m.errSubs = append(m.errSubs, errorSubscriber{id: id, fn: fn})
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.errSubs = slices.DeleteFunc(m.errSubs, func(s errorSubscriber) bool { return s.id == id })
	}
}

// notify calls every subscriber with updated, stopping at the first error.
func (m *Manager) notify(ctx context.Context, updated map[string]struct{}) error {
	m.mu.Lock()
	subs := slices.Clone(m.subs)
	m.mu.Unlock()
	for _, s := range subs {
		if err := s.fn(ctx, maps.Clone(updated)); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) notifyError(err error) {
	m.mu.Lock()
	subs := slices.Clone(m.errSubs)
	m.mu.Unlock()
	for _, s := range subs {
		s.fn(err)
	}
}

// lookup returns the option called name. It panics when the option is not
// registered, as attribute access on mitmproxy's OptManager raises.
// m.mu must be held.
func (m *Manager) lookup(name string) *option {
	o, ok := m.opts.Get(name)
	if !ok {
		panic("No such option: " + name)
	}
	return o
}

// Has reports whether an option called name is registered.
func (m *Manager) Has(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.opts.Has(name)
}

// Keys returns the registered option names in registration order.
func (m *Manager) Keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.opts.Keys()
}

// Items returns a snapshot of every registered option in registration order.
func (m *Manager) Items() []Option {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Option, 0, m.opts.Len())
	for _, o := range m.opts.All() {
		out = append(out, o.snapshot())
	}
	return out
}

// Lookup returns a snapshot of the option called name.
func (m *Manager) Lookup(name string) (Option, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.opts.Get(name)
	if !ok {
		return Option{}, false
	}
	return o.snapshot(), true
}

// Current returns a copy of the current value of the option called name, in
// its canonical Go representation (see [Value]). It panics when the option
// is not registered.
func (m *Manager) Current(name string) any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return copyValue(m.lookup(name).current())
}

// Default returns a copy of the default value of the option called name. It
// panics when the option is not registered.
func (m *Manager) Default(name string) any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return copyValue(m.lookup(name).def)
}

// HasChanged reports whether the option called name differs from its
// default. It panics when the option is not registered.
func (m *Manager) HasChanged(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	o := m.lookup(name)
	return !equalValues(o.current(), o.def)
}

// Get returns a copy of the current value of the option called name as T.
// It panics when the option is not registered or when T is not the Go type
// of the option (see [Type]).
func Get[T Value](m *Manager, name string) T {
	m.mu.Lock()
	defer m.mu.Unlock()
	o := m.lookup(name)
	t, ok := copyValue(o.current()).(T)
	if !ok {
		var zero T
		panic(fmt.Sprintf("option %s has type %s, not %T", name, o.typ, zero))
	}
	return t
}

// Bool returns the value of the [TypeBool] option called name.
func (m *Manager) Bool(name string) bool { return Get[bool](m, name) }

// Int returns the value of the [TypeInt] option called name.
func (m *Manager) Int(name string) int { return Get[int](m, name) }

// Str returns the value of the [TypeStr] option called name.
func (m *Manager) Str(name string) string { return Get[string](m, name) }

// Seq returns a copy of the value of the [TypeSeq] option called name.
func (m *Manager) Seq(name string) []string { return Get[[]string](m, name) }

// OptStr returns a copy of the value of the [TypeOptStr] option called name;
// nil means None.
func (m *Manager) OptStr(name string) *string { return Get[*string](m, name) }

// OptInt returns a copy of the value of the [TypeOptInt] option called name;
// nil means None.
func (m *Manager) OptInt(name string) *int { return Get[*int](m, name) }

// Update sets the options named in values and returns an
// [*UnknownOptionError] if values names options that are not registered.
//
// As in mitmproxy, the known options are applied even when some names are
// unknown. Unlike mitmproxy, every value is type-checked before any is
// applied, so a [*TypeError] leaves all options unchanged instead of
// applying the values that preceded the bad one.
func (m *Manager) Update(ctx context.Context, values map[string]any) error {
	unknown, err := m.UpdateKnown(ctx, values)
	if err != nil {
		return err
	}
	if len(unknown) > 0 {
		return &UnknownOptionError{Names: slices.Sorted(maps.Keys(unknown))}
	}
	return nil
}

// UpdateKnown sets the registered options named in values and returns the
// entries that name unregistered options.
//
// Subscribers are called once with the names of all updated options. If one
// returns an [*OptionsError], every option is restored to the value it had
// before the call, subscribers are notified again, and the error is
// returned.
func (m *Manager) UpdateKnown(ctx context.Context, values map[string]any) (unknown map[string]any, err error) {
	unknown = make(map[string]any)
	known := make(map[string]any, len(values))
	m.mu.Lock()
	for k, v := range values {
		o, ok := m.opts.Get(k)
		if !ok {
			unknown[k] = v
			continue
		}
		cv, err := coerce(k, o.typ, v)
		if err != nil {
			m.mu.Unlock()
			return nil, err
		}
		known[k] = cv
	}
	if len(known) == 0 {
		m.mu.Unlock()
		return unknown, nil
	}
	saved := m.saveLocked()
	for k, v := range known {
		o := m.lookup(k)
		o.value, o.isSet = v, true
	}
	m.mu.Unlock()

	updated := make(map[string]struct{}, len(known))
	for k := range known {
		updated[k] = struct{}{}
	}
	if err := m.notify(ctx, updated); err != nil {
		if oe, ok := errors.AsType[*OptionsError](err); ok {
			return nil, m.rollback(ctx, saved, updated, err, oe)
		}
		return nil, err
	}
	return unknown, nil
}

type savedValue struct {
	value any
	isSet bool
}

// saveLocked records every option value so that a failed update can be
// undone. m.mu must be held.
func (m *Manager) saveLocked() map[string]savedValue {
	saved := make(map[string]savedValue, m.opts.Len())
	for k, o := range m.opts.All() {
		saved[k] = savedValue{value: o.value, isSet: o.isSet}
	}
	return saved
}

// rollback restores saved, which m.saveLocked produced, after a subscriber
// rejected a change with err, whose *OptionsError is cause, and returns err.
func (m *Manager) rollback(ctx context.Context, saved map[string]savedValue, updated map[string]struct{}, err error, cause *OptionsError) error {
	m.notifyError(cause)
	m.mu.Lock()
	for k, s := range saved {
		if o, ok := m.opts.Get(k); ok {
			o.value, o.isSet = s.value, s.isSet
		}
	}
	m.mu.Unlock()
	if nerr := m.notify(ctx, updated); nerr != nil {
		return errors.Join(err, nerr)
	}
	return err
}

// Reset restores every option to its default and notifies subscribers with
// all option names. It returns the error a subscriber returned, if any; the
// reset is not rolled back.
func (m *Manager) Reset(ctx context.Context) error {
	m.mu.Lock()
	updated := make(map[string]struct{}, m.opts.Len())
	for k, o := range m.opts.All() {
		o.value, o.isSet = nil, false
		updated[k] = struct{}{}
	}
	m.mu.Unlock()
	return m.notify(ctx, updated)
}

// UpdateDeferred sets the registered options named in values and keeps the
// remaining entries until options of those names are registered and
// [Manager.ProcessDeferred] is called.
func (m *Manager) UpdateDeferred(ctx context.Context, values map[string]any) error {
	unknown, err := m.UpdateKnown(ctx, values)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range slices.Sorted(maps.Keys(unknown)) {
		m.deferred.Set(k, unknown[k])
	}
	return nil
}

// Deferred returns a copy of the values waiting for their options to be
// registered. Values stored by [Manager.SetDeferred] are [Unparsed]; values
// stored from configuration files are kept as decoded.
func (m *Manager) Deferred() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]any, m.deferred.Len())
	for k, v := range m.deferred.All() {
		if u, ok := v.(Unparsed); ok {
			v = slices.Clone(u)
		}
		out[k] = v
	}
	return out
}
