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
	"github.com/zchee/mitmproxy-go/flow"
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
	// Nil means [slog.Default] as it is at the time of each record, so a
	// program may install its default logger after creating the Manager.
	Logger *slog.Logger

	// OnDispatchStart and OnDispatchEnd, when set, are called each time the
	// dispatch lock is taken and just before it is released, by whichever
	// goroutine takes it. They are process-level observability callbacks,
	// for example for lock hold-time metrics. They are not suited to
	// per-connection work such as pausing one connection's idle watchdog,
	// because they fire for every acquisition by any goroutine; the proxy
	// disarms a connection's watchdog in its own hook runner instead.
	OnDispatchStart func()
	OnDispatchEnd   func()
}

// Manager registers addons and dispatches hooks to them (mitmproxy's
// AddonManager). All dispatch happens under the manager's dispatch lock; see
// the package documentation.
type Manager struct {
	d       dispatcher
	options *options.Manager
	cmds    *command.Manager
	logger  *slog.Logger

	// mu guards chain and lookup. Changes happen under the dispatch lock as
	// well, so that hooks see a consistent set of addons; mu lets Get and
	// Len be called without the dispatch lock. Addon code never runs with
	// mu held.
	mu sync.RWMutex
	// chain is copy-on-write: a change publishes a new slice and never
	// writes to the elements of the old one, so a hook chain iterates the
	// slice it read without copying it, even after [Concurrent] released
	// the lock and the chain changed.
	chain  []any
	lookup map[string]any
	// commands lists, per addon passed to Register, the commands it added
	// through its Loader, so that removing the addon removes them.
	commands map[any][]string

	unsubscribe func()
}

// NewManager returns a Manager that adds addon options to opts and addon
// commands to cmds, and fires the configure hook whenever opts change. It
// installs a [command.Runner] on cmds (see [command.Manager.SetRunner]) that
// runs every command under the dispatch lock as a synchronous call; see
// [Manager.Call].
//
// A command registry serves one Manager. NewManager panics with an error
// wrapping [command.ErrRunnerSet] when cmds already has a Runner, such as
// the one another Manager installed, because the commands would otherwise
// run under this Manager's dispatch lock while the other one dispatches
// hooks to their addons.
func NewManager(opts *options.Manager, cmds *command.Manager, cfg Config) *Manager {
	m := &Manager{
		d:        dispatcher{onStart: cfg.OnDispatchStart, onEnd: cfg.OnDispatchEnd},
		options:  opts,
		cmds:     cmds,
		logger:   cfg.Logger,
		lookup:   make(map[string]any),
		commands: make(map[any][]string),
	}
	// The Runner goes first, so that a refused registry leaves no option
	// subscription behind.
	if err := cmds.SetRunner(m.runCommand); err != nil {
		panic(fmt.Errorf("addon: NewManager: %w", err))
	}
	m.unsubscribe = opts.Subscribe(func(ctx context.Context, updated map[string]struct{}) error {
		return m.d.do(ctx, func(ctx context.Context) error {
			return m.trigger(ctx, ConfigureHook{Updated: updated})
		})
	})
	return m
}

// runCommand is the [command.Runner] the Manager installs on its command
// registry: it runs a command under the dispatch lock, in a frame that marks
// a synchronous call.
func (m *Manager) runCommand(ctx context.Context, name string, run func(context.Context) (any, error)) (any, error) {
	var res any
	err := m.d.do(ctx, func(ctx context.Context) error {
		var err error
		res, err = run(inSync(ctx, "command "+name))
		return err
	})
	return res, err
}

// log returns the logger for the manager's own records.
func (m *Manager) log() *slog.Logger {
	if m.logger != nil {
		return m.logger
	}
	return slog.Default()
}

// Close stops firing the configure hook for option changes. It does not
// remove the addons; use [Manager.Clear] for that.
func (m *Manager) Close() {
	m.unsubscribe()
}

// Options returns the option registry addons add their options to.
func (m *Manager) Options() *options.Manager { return m.options }

// Commands returns the command registry addons add their commands to.
func (m *Manager) Commands() *command.Manager { return m.cmds }

// Do runs fn under the dispatch lock and passes it a context that lets
// calls inside fn, such as an option change that fires configure, re-enter
// the lock instead of deadlocking. A ctx that already carries a valid
// dispatch frame is re-entered the same way. Goroutines outside hooks must
// change addon state, flows and options only through Do.
func (m *Manager) Do(ctx context.Context, fn func(ctx context.Context) error) error {
	return m.d.do(ctx, fn)
}

// Call runs the command registered under name with args under the
// dispatch lock, the way [Manager.Do] runs a function, and returns its
// result. It is [command.Manager.Call] on the Manager's command registry,
// which runs every command the same way through the runner NewManager
// installed. A ctx that carries a valid dispatch frame, such as the context
// of a hook or of a command calling another command, re-enters the hold of
// the lock instead of taking it again.
//
// The command runs as a synchronous call, as a mitmproxy command does: it
// cannot release the lock, and [Concurrent] called with its context
// returns an error wrapping [ErrSyncContext].
func (m *Manager) Call(ctx context.Context, name string, args ...any) (any, error) {
	return m.cmds.Call(ctx, name, args...)
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
			m.chain = append(slices.Clip(m.chain), a)
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
// sub-addons, is taken, and an addon with a near miss of a hook handler: a
// method named after the handler whose first parameter is a
// [context.Context] but whose signature does not match the handler
// interface, which would otherwise never be called. A method of that name
// without a leading context, such as the Done of an embedded
// [sync.WaitGroup] or the Error of an addon that implements error, is not
// a handler and is never called. It then runs the load hook on the addon
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
	// Name, Addons and the logger are addon code, so mu is taken only
	// around the lookups, never across those calls.
	for a := range traverse(addon) {
		if err := checkAddon(a); err != nil {
			return err
		}
		name := addonName(a)
		m.mu.RLock()
		_, taken := m.lookup[name]
		m.mu.RUnlock()
		if taken {
			return fmt.Errorf("%w: An addon called '%s' already exists.", ErrAddonManager, name) //nolint:staticcheck // mitmproxy's message, shown to users verbatim.
		}
		if _, ok := a.(AddLogHandler); ok {
			m.log().WarnContext(ctx, "The add_log event has been deprecated, use log/slog instead.", "addon", name)
		}
	}

	// Each addon of the tree gets a Loader of its own, so that the
	// commands it adds belong to it and leave with it when it alone is
	// removed. The frame of a synchronous dispatch is never replaced, so
	// every handler can be called with it.
	ctx = inSync(ctx, LoadHook{}.Name()+" hook")
	var loaded []any
	for a := range traverse(addon) {
		loaded = append(loaded, a)
		if _, err := (LoadHook{Loader: &Loader{m: m, addon: a}}).invoke(ctx, a); err != nil {
			// The addon is not registered, so nothing could remove it
			// later; take back the commands the loads added. Only the
			// addons whose load ran have a Loader, and a load may have
			// dropped one of them from the tree, so they are the ones
			// recorded here rather than the ones the tree yields now.
			// A load may also have registered one of them on its own,
			// through a nested Register; that one stays registered, and
			// its commands leave when it is removed.
			for _, a := range loaded {
				if !m.registered(a) {
					m.unregisterCommands(a)
				}
			}
			return err
		}
	}

	// Traverse again: load may have changed the sub-addons, as it does in
	// mitmproxy.
	var (
		tree  []any
		names []string
	)
	for a := range traverse(addon) {
		tree = append(tree, a)
		names = append(names, addonName(a))
	}
	m.mu.Lock()
	for i, a := range tree {
		m.lookup[names[i]] = a
	}
	m.mu.Unlock()

	return m.options.ProcessDeferred(ctx)
}

// Remove removes addon and its sub-addons, then runs the done hook on
// them, then unregisters the commands they added, so that loading the
// addon again can add them again. An addon that is not in the chain
// because a parent addon manages it must also be removed from that
// parent's sub-addons by the parent.
func (m *Manager) Remove(ctx context.Context, addon any) error {
	return m.d.do(ctx, func(ctx context.Context) error {
		if addon == nil {
			return fmt.Errorf("%w: cannot remove a nil addon", ErrAddonManager)
		}
		// A registered addon is comparable, so a value that is not cannot
		// be one of them, and comparing it would panic.
		if !reflect.ValueOf(addon).Comparable() {
			return fmt.Errorf("%w: addon %s is an uncomparable value of type %T and cannot be registered", ErrAddonManager, addonName(addon), addon)
		}
		for a := range traverse(addon) {
			name := addonName(a)
			m.mu.Lock()
			_, ok := m.lookup[name]
			if ok {
				if reflect.ValueOf(a).Comparable() {
					m.chain = slices.DeleteFunc(slices.Clone(m.chain), func(c any) bool { return c == a })
				}
				delete(m.lookup, name)
			}
			m.mu.Unlock()
			if !ok {
				return fmt.Errorf("%w: No such addon: %s", ErrAddonManager, name)
			}
		}
		defer func() {
			for a := range traverse(addon) {
				m.unregisterCommands(a)
			}
		}()
		return m.invokeTree(inSync(ctx, DoneHook{}.Name()+" hook"), addon, DoneHook{})
	})
}

// Clear runs the done hook on every addon in the chain, then removes them
// all and unregisters the commands they added. When a done handler fails,
// Clear returns its error and leaves the addons registered.
func (m *Manager) Clear(ctx context.Context) error {
	return m.d.do(ctx, func(ctx context.Context) error {
		for _, a := range m.Chain() {
			if err := m.invokeTree(inSync(ctx, DoneHook{}.Name()+" hook"), a, DoneHook{}); err != nil {
				return err
			}
		}
		m.mu.Lock()
		owned := m.commands
		m.chain = nil
		m.lookup = make(map[string]any)
		m.commands = make(map[any][]string)
		m.mu.Unlock()
		for _, names := range owned {
			for _, n := range names {
				m.cmds.Unregister(n)
			}
		}
		return nil
	})
}

// Hook runs hook on every addon in the chain like [Manager.Trigger], and
// then, when hook carries a flow, runs the update hook with that flow, in
// the same hold of the dispatch lock (mitmproxy's handle_lifecycle). The
// proxy calls Hook for every lifecycle event of a connection or flow on
// the goroutine that handles it.
//
// The handlers of both hooks run in the caller's hold of the lock, not in a
// nested one, so a flow hook dispatched at the outermost level may call
// [Concurrent]. Update runs after a handler error, which is logged, and
// after a handler halted the first hook with [ErrAddonHalt], as in
// mitmproxy. It is skipped only when the first hook's dispatch fails: a
// handler returned an [*options.OptionsError], or ctx carries a stale
// frame.
func (m *Manager) Hook(ctx context.Context, hook Hook) error {
	return m.d.do(ctx, func(ctx context.Context) error {
		return m.hookLocked(ctx, hook)
	})
}

// hookLocked is the body of [Manager.Hook]: the hook chain, then update for
// a flow hook, run with the dispatch lock held through the frame in ctx.
func (m *Manager) hookLocked(ctx context.Context, hook Hook) error {
	if err := m.trigger(ctx, hook); err != nil {
		return err
	}
	f := HookFlow(hook)
	if f == nil {
		return nil
	}
	return m.trigger(ctx, UpdateHook{Flows: []flow.Flow{f}})
}

// HookFlow returns the flow that hook carries, or nil for a hook that does
// not carry one (and for a flow hook whose flow field is nil). The proxy's
// hook runner uses it to wait for an intercepted flow and to snapshot the
// flow's fields without knowing every hook type.
func HookFlow(hook Hook) flow.Flow {
	if fh, ok := hook.(flowHook); ok {
		return fh.flowArg()
	}
	return nil
}

// HookFunc runs prepare, then hook's chain and update exactly like
// [Manager.Hook], and then finish, all in one hold of the dispatch lock, so
// that no [Manager.Do] callback and no other hook can observe the state
// prepare produced without the hook having run. The proxy's hook runner is
// built on it: a layer stores what it has read into the flow in prepare
// (the only place outside [Manager.Do] where a layer may write a flow field
// handlers can see), and the hook fires on that state atomically.
//
// prepare and finish run with a frame that marks a synchronous dispatch:
// [Concurrent] called from either returns an error wrapping
// [ErrSyncContext], so neither can release the lock. The hook's handlers
// run with the ordinary frame of the hold, exactly as under [Manager.Hook],
// so at the outermost dispatch level they may call [Concurrent] (which
// releases the lock; the single-hold guarantee then covers prepare and the
// chain up to that handler). A prepare error skips the hook and finish and
// is returned. finish runs only when prepare and the dispatch succeeded;
// the hook runner uses it to read a consistent snapshot after update handlers
// have made their final edits, before another dispatch can change the flow.
// It receives the current frame, refreshed after any Concurrent call. Either
// callback may be nil.
//
// [Manager.Do] with [Manager.Hook] inside it is not a substitute: the inner
// call re-enters one level deeper, where [Concurrent] is refused.
func (m *Manager) HookFunc(ctx context.Context, prepare func(context.Context) error, hook Hook, finish func(context.Context)) error {
	return m.d.do(ctx, func(ctx context.Context) error {
		if prepare != nil {
			if err := prepare(inSync(ctx, "HookFunc prepare")); err != nil {
				return err
			}
		}
		if err := m.hookLocked(ctx, hook); err != nil {
			return err
		}
		if finish != nil {
			ctx = withFrame(ctx, m.d.current(frameFrom(ctx)))
			finish(inSync(ctx, "HookFunc finish"))
		}
		return nil
	})
}

// Trigger runs hook on every addon in the chain, each addon before its
// sub-addons, under the dispatch lock.
//
// The configure and load hooks run as a synchronous dispatch, in which
// [Concurrent] returns an error wrapping [ErrSyncContext], whether they are
// fired through Trigger, [Manager.Hook], an option change or
// [Manager.InvokeSync]: mitmproxy dispatches both only synchronously, with
// trigger and invoke_addon_sync, never with trigger_event.
//
// A handler error is logged and the hook goes on to the next addon in the
// chain, skipping the sub-addons of the failing one that it had not reached
// yet; a handler panic is recovered and handled the same way. A handler
// error wrapping [ErrAddonHalt] stops the hook without being logged. An
// [*options.OptionsError] stops the hook and is returned, so that an option
// change that a configure handler rejects is rolled back. Trigger returns
// an error otherwise only when ctx carries a stale dispatch frame.
//
// A handler that presents a stale frame, for example a context it kept
// from an earlier hook, is not treated as an ordinary failing handler: the
// panic test binaries raise for it is not recovered, so the misuse fails
// the test. Other builds log the [ErrStaleFrame] error like any handler
// error.
func (m *Manager) Trigger(ctx context.Context, hook Hook) error {
	return m.d.do(ctx, func(ctx context.Context) error {
		return m.trigger(ctx, hook)
	})
}

// trigger is Trigger for a caller that holds the dispatch lock through the
// frame in ctx. It runs the handlers in that frame instead of a nested one,
// so that handlers of a hook dispatched at the outermost level may call
// [Concurrent], unless the hook is one that always runs synchronously.
func (m *Manager) trigger(ctx context.Context, hook Hook) error {
	if syncHook(hook) {
		ctx = inSync(ctx, hook.Name()+" hook")
	}
	m.mu.RLock()
	chain := m.chain
	m.mu.RUnlock()
	for _, a := range chain {
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
		m.log().ErrorContext(ctx, "Addon error: "+err.Error(), "addon", addonName(a), "hook", hook.Name())
	}
	return nil
}

// syncHook reports whether hook is one that mitmproxy dispatches only
// synchronously, so that its handlers can never release the dispatch lock.
// It decides by the hook's name, as the rest of the dispatch does, so that
// a pointer to the hook, which is a [Hook] as well, is treated the same.
// A hook type that embeds ConfigureHook or LoadHook but returns another
// name from Name is therefore not synchronous, although it calls the same
// handlers.
func syncHook(hook Hook) bool {
	switch hook.Name() {
	case ConfigureHook{}.Name(), LoadHook{}.Name():
		return true
	}
	return false
}

// InvokeSync runs hook on addon and its sub-addons, depth first, under the
// dispatch lock, as a synchronous dispatch (mitmproxy's invoke_addon_sync).
// A ctx that carries a valid dispatch frame re-enters the hold of the lock
// instead of taking it again.
//
// addon need not be registered: a script loader uses InvokeSync to fire
// configure and running on a script it has just loaded, and script.run to
// fire the events of a flow on a script it never registers. [Concurrent]
// called with a handler's context returns an error wrapping
// [ErrSyncContext], whichever the hook. The first handler error stops the
// dispatch and is returned as it is, without being logged, and a handler
// panic is not recovered; mitmproxy's callers wrap invoke_addon_sync in
// safecall when they want either logged.
func (m *Manager) InvokeSync(ctx context.Context, addon any, hook Hook) error {
	return m.d.do(ctx, func(ctx context.Context) error {
		return m.invokeTree(inSync(ctx, hook.Name()+" hook"), addon, hook)
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
			if e, ok := r.(error); ok && errors.Is(e, ErrStaleFrame) {
				panic(r)
			}
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

// checkAddon refuses an addon that the manager cannot track or that has a
// near miss of a hook handler: a method with the handler's name and a
// leading context.Context but another signature, which would never be
// called. A method with the handler's name and no leading context is an
// ordinary method that happens to share the name, and is left alone.
func checkAddon(a any) error {
	if a == nil {
		return fmt.Errorf("%w: nil sub-addon", ErrAddonManager)
	}
	t := reflect.TypeOf(a)
	v := reflect.ValueOf(a)
	// Value.Comparable also looks at the dynamic values of interface
	// fields: a struct type is comparable, but comparing two values of it
	// panics when such a field holds a slice, a map or a function.
	if !v.Comparable() {
		return fmt.Errorf("%w: addon %s is an uncomparable value of type %v; register a pointer", ErrAddonManager, addonName(a), t)
	}
	for _, s := range hookSpecs {
		want := s.handler.Method(0)
		got := v.MethodByName(want.Name)
		if !got.IsValid() || t.Implements(s.handler) {
			continue
		}
		if mt := got.Type(); mt.NumIn() > 0 && mt.In(0) == contextType {
			return fmt.Errorf("%w: addon %s: handler %s for the %s hook has type %v, want %v", ErrAddonManager, addonName(a), want.Name, s.hook.Name(), got.Type(), want.Type)
		}
	}
	return nil
}

var contextType = reflect.TypeFor[context.Context]()

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
		l.m.log().WarnContext(ctx, "Over-riding existing option "+name, "addon", addonName(l.addon))
	}
	var opts []options.AddOption
	if choices != nil {
		opts = append(opts, options.WithChoices(choices...))
	}
	return l.m.options.Add(ctx, name, typ, def, help, opts...)
}

// AddCommand adds a command to the command registry (mitmproxy's
// Loader.add_command). See [command.Manager.Register] for the functions a
// command may be; a function whose first parameter is not a
// [context.Context] is refused with an error wrapping
// [command.ErrSignature]. The command belongs to the addon whose load
// received l, which may be a sub-addon, and is unregistered when that addon
// is removed. A name another addon's command already has is refused with
// [command.ErrDuplicateCommand].
func (l *Loader) AddCommand(name string, fn any, opts ...command.Option) error {
	// A sub-addon that its parent added during load was not checked at
	// registration; one that cannot be compared cannot own commands.
	if !reflect.ValueOf(l.addon).Comparable() {
		return fmt.Errorf("%w: addon %s is an uncomparable value of type %T; register a pointer", ErrAddonManager, addonName(l.addon), l.addon)
	}
	if err := l.m.cmds.Register(name, fn, opts...); err != nil {
		return err
	}
	l.m.mu.Lock()
	l.m.commands[l.addon] = append(l.m.commands[l.addon], name)
	l.m.mu.Unlock()
	return nil
}

// registered reports whether addon itself, not only another addon of its
// name, is registered.
func (m *Manager) registered(addon any) bool {
	// Comparing two interface values that hold the same uncomparable type
	// panics, and the lookup can hold such a sub-addon, which a load added
	// after the registration checks ran.
	if addon == nil || !reflect.ValueOf(addon).Comparable() {
		return false
	}
	name := addonName(addon) // addon code, so outside mu
	m.mu.RLock()
	r, ok := m.lookup[name]
	m.mu.RUnlock()
	return ok && reflect.ValueOf(r).Comparable() && r == addon
}

// unregisterCommands removes the commands addon added through its Loader.
func (m *Manager) unregisterCommands(addon any) {
	if addon == nil || !reflect.ValueOf(addon).Comparable() {
		return
	}
	m.mu.Lock()
	names := m.commands[addon]
	delete(m.commands, addon)
	m.mu.Unlock()
	for _, n := range names {
		m.cmds.Unregister(n)
	}
}
