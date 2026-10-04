// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package addon

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"
	"sync"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/options"
)

var (
	// ErrAddonHalt stops a hook from reaching the addons after the handler
	// that returns it, directly or wrapped (mitmproxy's AddonHalt).
	ErrAddonHalt = errors.New("addon: halt")

	// ErrAddonManager reports a registration or removal the manager refuses
	// (mitmproxy's AddonManagerError).
	ErrAddonManager = errors.New("addon manager")
)

// Namer is implemented by an addon that chooses its own name. An addon
// without it is named after its type, lower-cased, as mitmproxy names an
// addon without a name attribute after its class.
type Namer interface {
	Name() string
}

// Parent is implemented by an addon that has sub-addons. Hooks reach the
// sub-addons after the parent, depth first, and registering or removing the
// parent registers or removes them too. Addons is called on every dispatch,
// so a parent may change its sub-addons, as mitmproxy's script loader does
// when it reloads a script.
type Parent interface {
	Addons() []any
}

// Config configures a [Manager].
type Config struct {
	// Logger receives the errors handlers return and the panics they raise.
	// Nil means [slog.Default].
	Logger *slog.Logger

	// OnDispatchStart and OnDispatchEnd, when set, are called each time the
	// dispatch lock is taken and just before it is released. The proxy uses
	// them to stop a connection's idle watchdog while hooks run.
	OnDispatchStart func()
	OnDispatchEnd   func()
}

// Manager registers addons and dispatches hooks to them (mitmproxy's
// AddonManager). All dispatch happens under the manager's dispatch lock; see
// the package documentation.
type Manager struct {
	d        dispatcher
	options  *options.Manager
	commands *command.Manager
	logger   *slog.Logger

	// mu guards chain and lookup. Changes happen under the dispatch lock as
	// well, so that hooks see a consistent set of addons; mu lets Get and
	// Len be called without the dispatch lock. Addon code never runs with
	// mu held.
	mu     sync.RWMutex
	chain  []any
	lookup map[string]any

	unsubscribe func()
}

// NewManager returns a Manager that adds addon options to opts and addon
// commands to cmds, and fires the configure hook whenever opts change.
func NewManager(opts *options.Manager, cmds *command.Manager, cfg Config) *Manager {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	m := &Manager{
		d:        dispatcher{onStart: cfg.OnDispatchStart, onEnd: cfg.OnDispatchEnd},
		options:  opts,
		commands: cmds,
		logger:   logger,
		lookup:   make(map[string]any),
	}
	m.unsubscribe = opts.Subscribe(func(ctx context.Context, updated map[string]struct{}) error {
		return m.Trigger(ctx, ConfigureHook{Updated: updated})
	})
	return m
}

// Close stops firing the configure hook for option changes. It does not
// remove the addons; use [Manager.Clear] for that.
func (m *Manager) Close() {
	m.unsubscribe()
}

// Options returns the option registry addons add their options to.
func (m *Manager) Options() *options.Manager { return m.options }

// Commands returns the command registry addons add their commands to.
func (m *Manager) Commands() *command.Manager { return m.commands }

// Do runs fn under the dispatch lock and passes it a context that lets
// calls inside fn, such as an option change that fires configure, re-enter
// the lock instead of deadlocking. A ctx that already carries a valid
// dispatch frame is re-entered the same way. Goroutines outside hooks must
// change addon state, flows and options only through Do.
func (m *Manager) Do(ctx context.Context, fn func(ctx context.Context) error) error {
	return m.d.do(ctx, fn)
}

// Get returns the registered addon named name, or nil.
func (m *Manager) Get(name string) any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lookup[name]
}

// Contains reports whether an addon with the name of a is registered.
func (m *Manager) Contains(a any) bool {
	return m.Get(addonName(a)) != nil
}

// Len returns the number of addons in the chain, not counting sub-addons.
func (m *Manager) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.chain)
}

// Chain returns the addons in the chain, not counting sub-addons, in the
// order hooks reach them.
func (m *Manager) Chain() []any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Clone(m.chain)
}

// Add registers each addon (see [Manager.Register]) and appends it to the
// chain. It stops at the first addon that fails to register.
func (m *Manager) Add(ctx context.Context, addons ...any) error {
	return m.d.do(ctx, func(ctx context.Context) error {
		for _, a := range addons {
			if err := m.register(ctx, a); err != nil {
				return err
			}
			m.mu.Lock()
			m.chain = append(m.chain, a)
			m.mu.Unlock()
		}
		return nil
	})
}

// Register registers addon and its sub-addons without appending addon to
// the chain, for an addon that manages other addons itself and dispatches
// to them as its sub-addons.
//
// Registration refuses an addon whose name, or the name of one of its
// sub-addons, is taken, and an addon with a method named after a hook
// handler whose signature does not match the handler interface, which
// would otherwise never be called. It then runs the load hook on the addon
// and its sub-addons, records their names, and applies the option values
// that were deferred until an addon added the option. An error from a load
// handler is returned; the addons whose load already ran stay loaded, as in
// mitmproxy.
func (m *Manager) Register(ctx context.Context, addon any) error {
	return m.d.do(ctx, func(ctx context.Context) error {
		return m.register(ctx, addon)
	})
}

func (m *Manager) register(ctx context.Context, addon any) error {
	if addon == nil {
		return fmt.Errorf("%w: cannot register a nil addon", ErrAddonManager)
	}
	m.mu.RLock()
	var err error
	for a := range traverse(addon) {
		if err = checkAddon(a); err != nil {
			break
		}
		name := addonName(a)
		if _, taken := m.lookup[name]; taken {
			err = fmt.Errorf("%w: An addon called '%s' already exists.", ErrAddonManager, name) //nolint:staticcheck // mitmproxy's message, shown to users verbatim.
			break
		}
		if _, ok := a.(AddLogHandler); ok {
			m.logger.WarnContext(ctx, "The add_log event has been deprecated, use log/slog instead.", "addon", name)
		}
	}
	m.mu.RUnlock()
	if err != nil {
		return err
	}

	if err := m.invokeTree(ctx, addon, LoadHook{Loader: &Loader{m: m, addon: addon}}); err != nil {
		return err
	}

	m.mu.Lock()
	for a := range traverse(addon) {
		m.lookup[addonName(a)] = a
	}
	m.mu.Unlock()

	return m.options.ProcessDeferred(ctx)
}

// Remove removes addon and its sub-addons, then runs the done hook on
// them. An addon that is not in the chain because a parent addon manages
// it must also be removed from that parent's sub-addons by the parent.
func (m *Manager) Remove(ctx context.Context, addon any) error {
	return m.d.do(ctx, func(ctx context.Context) error {
		if addon == nil {
			return fmt.Errorf("%w: cannot remove a nil addon", ErrAddonManager)
		}
		for a := range traverse(addon) {
			name := addonName(a)
			m.mu.Lock()
			_, ok := m.lookup[name]
			if ok {
				if reflect.TypeOf(a).Comparable() {
					m.chain = slices.DeleteFunc(m.chain, func(c any) bool { return c == a })
				}
				delete(m.lookup, name)
			}
			m.mu.Unlock()
			if !ok {
				return fmt.Errorf("%w: No such addon: %s", ErrAddonManager, name)
			}
		}
		return m.invokeTree(ctx, addon, DoneHook{})
	})
}

// Clear runs the done hook on every addon in the chain and removes them
// all.
func (m *Manager) Clear(ctx context.Context) error {
	return m.d.do(ctx, func(ctx context.Context) error {
		for _, a := range m.Chain() {
			if err := m.invokeTree(ctx, a, DoneHook{}); err != nil {
				return err
			}
		}
		m.mu.Lock()
		m.chain = nil
		m.lookup = make(map[string]any)
		m.mu.Unlock()
		return nil
	})
}

// Trigger runs hook on every addon in the chain, each addon before its
// sub-addons, under the dispatch lock.
//
// A handler error is logged and the hook goes on to the next addon in the
// chain, skipping the sub-addons of the failing one that it had not reached
// yet; a handler panic is recovered and handled the same way. A handler
// error wrapping [ErrAddonHalt] stops the hook without being logged. An
// [*options.OptionsError] stops the hook and is returned, so that an option
// change that a configure handler rejects is rolled back. Trigger returns
// an error otherwise only when ctx carries a stale dispatch frame.
func (m *Manager) Trigger(ctx context.Context, hook Hook) error {
	return m.d.do(ctx, func(ctx context.Context) error {
		for _, a := range m.Chain() {
			err := m.safeInvokeTree(ctx, a, hook)
			if err == nil {
				continue
			}
			if errors.Is(err, ErrAddonHalt) {
				return nil
			}
			if _, ok := errors.AsType[*options.OptionsError](err); ok {
				return err
			}
			m.logger.ErrorContext(ctx, "Addon error: "+err.Error(), "addon", addonName(a), "hook", hook.Name())
		}
		return nil
	})
}

// panicError is a recovered handler panic.
type panicError struct {
	value any
	stack []byte
}

func (e *panicError) Error() string { return fmt.Sprintf("panic: %v\n%s", e.value, e.stack) }

// safeInvokeTree is invokeTree with a handler panic turned into an error.
func (m *Manager) safeInvokeTree(ctx context.Context, addon any, hook Hook) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &panicError{value: r, stack: debug.Stack()}
		}
	}()
	return m.invokeTree(ctx, addon, hook)
}

// invokeTree runs hook on addon and its sub-addons, depth first, and stops
// at the first error. It must be called with the dispatch lock held through
// the frame in ctx. Each handler gets the current frame of the hold, which
// a [Concurrent] call in an earlier handler may have replaced.
func (m *Manager) invokeTree(ctx context.Context, addon any, hook Hook) error {
	f := frameFrom(ctx)
	for a := range traverse(addon) {
		if _, err := hook.invoke(withFrame(ctx, m.d.current(f)), a); err != nil {
			return err
		}
	}
	return nil
}

// traverse yields addon and then its sub-addons, depth first (mitmproxy's
// traverse).
func traverse(addon any) iter.Seq[any] {
	return func(yield func(any) bool) {
		walk(addon, yield)
	}
}

func walk(addon any, yield func(any) bool) bool {
	if !yield(addon) {
		return false
	}
	if p, ok := addon.(Parent); ok {
		for _, c := range p.Addons() {
			if !walk(c, yield) {
				return false
			}
		}
	}
	return true
}

// addonName returns the name addon is registered under.
func addonName(addon any) string {
	if n, ok := addon.(Namer); ok {
		return n.Name()
	}
	t := reflect.TypeOf(addon)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil {
		return "<nil>"
	}
	if t.Name() != "" {
		return strings.ToLower(t.Name())
	}
	return strings.ToLower(t.String())
}

// checkAddon refuses an addon that the manager cannot track or whose hook
// methods would never be called.
func checkAddon(a any) error {
	if a == nil {
		return fmt.Errorf("%w: nil sub-addon", ErrAddonManager)
	}
	t := reflect.TypeOf(a)
	if !t.Comparable() {
		return fmt.Errorf("%w: addon %s has the uncomparable type %v; register a pointer", ErrAddonManager, addonName(a), t)
	}
	v := reflect.ValueOf(a)
	for _, s := range hookSpecs {
		want := s.handler.Method(0)
		if got := v.MethodByName(want.Name); got.IsValid() && !t.Implements(s.handler) {
			return fmt.Errorf("%w: addon %s: handler %s for the %s hook has type %v, want %v", ErrAddonManager, addonName(a), want.Name, s.hook.Name(), got.Type(), want.Type)
		}
	}
	return nil
}

// Loader is passed to the load hook. Through it an addon adds its options
// and commands.
type Loader struct {
	m     *Manager
	addon any
}

// AddOption adds an option to the option registry (mitmproxy's
// Loader.add_option). help should be one paragraph without line breaks
// and without the type, which frontends add themselves.
//
// Adding an option that exists with the same type, default, help and
// choices does nothing, so that an addon can be loaded again. Adding one
// with a different signature logs a warning and replaces it.
func (l *Loader) AddOption(ctx context.Context, name string, typ options.Type, def any, help string, choices ...string) error {
	if existing, ok := l.m.options.Lookup(name); ok {
		same := existing.Type() == typ &&
			reflect.DeepEqual(existing.Default(), def) &&
			existing.Help() == help &&
			slices.Equal(existing.Choices(), choices)
		if same {
			return nil
		}
		l.m.logger.WarnContext(ctx, "Over-riding existing option "+name, "addon", addonName(l.addon))
	}
	var opts []options.AddOption
	if choices != nil {
		opts = append(opts, options.WithChoices(choices...))
	}
	return l.m.options.Add(ctx, name, typ, def, help, opts...)
}

// AddCommand adds a command to the command registry (mitmproxy's
// Loader.add_command). See [command.Manager.Register] for the functions a
// command may be.
func (l *Loader) AddCommand(name string, fn any, opts ...command.Option) error {
	return l.m.commands.Register(name, fn, opts...)
}
