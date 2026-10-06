// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package command manages typed commands that addons register and that the
// frontends invoke by name.
//
// A command is an ordinary Go function whose first parameter is a
// [context.Context]. Its parameter and result types are checked when it is
// registered: every parameter after the context must map to a command type
// identity ([Type]), and so must the result, mirroring the annotation checks
// mitmproxy performs when it builds a Command.
//
// mitmproxy's commands take no context. The port requires one because a
// command runs under the addon dispatch lock, which Go cannot re-enter: the
// context carries the dispatch frame that lets an option change or a hook
// fired by the command run inside the caller's hold of the lock instead of
// waiting for it forever.
//
// Help text set with [WithHelp] is laid out as mitmproxy lays out a
// command's docstring: surrounding whitespace removed, then re-wrapped to
// 70 columns with Python's textwrap.wrap, which joins paragraphs and
// indented lines into one run of text.
package command

import (
	"context"
	"fmt"
	"iter"
	"reflect"
	"strings"
	"sync"

	"github.com/zchee/mitmproxy-go/internal/textwrap"
	"github.com/zchee/mitmproxy-go/omap"
)

// Param describes one parameter of a command.
type Param struct {
	// Name is the parameter name shown in signature help.
	Name string
	// Type is the parameter's type identity. For a variadic parameter it is
	// the identity of each element.
	Type Type
	// Variadic reports whether the parameter takes any number of trailing
	// arguments, like Python's *args.
	Variadic bool
}

// String returns the parameter as signature help prints it: the name,
// prefixed with "*" when the parameter is variadic.
func (p Param) String() string {
	if p.Variadic {
		return "*" + p.Name
	}
	return p.Name
}

// Command is a registered command.
type Command struct {
	// Name is the name the command is called by, for example "view.flows.add".
	Name string
	// Help is the command's help text; it is empty when none was given.
	Help string
	// Params lists the command's parameters in call order. The leading
	// context.Context parameter of the function is not listed.
	Params []Param
	// Return is the identity of the command's result, or nil when the
	// command returns nothing.
	Return Type

	fn       reflect.Value
	defaults []reflect.Value
	required int
	hasValue bool // fn returns a value before the optional error
	hasErr   bool // fn's last result is an error
}

// SignatureHelp returns the one-line signature mitmproxy prints for the
// command, for example "varargs one *var -> str[]".
func (c *Command) SignatureHelp() string {
	params := make([]string, len(c.Params))
	for i, p := range c.Params {
		params[i] = p.String()
	}
	var ret string
	if c.Return != nil {
		ret = " -> " + c.Return.Display()
	}
	return c.Name + " " + strings.Join(params, " ") + ret
}

// Option configures a command at registration.
type Option func(*options)

type argumentOverride struct {
	name string
	typ  Type
}

type options struct {
	help      string
	names     []string
	overrides []argumentOverride
	defaults  map[string]any
}

// WithHelp sets the command's help text. Surrounding whitespace is removed
// and the rest is re-wrapped to 70 columns, its lines joined by newlines, as
// mitmproxy does with "\n".join(textwrap.wrap(doc.strip())).
func WithHelp(help string) Option {
	return func(o *options) { o.help = strings.Join(textwrap.Wrap(strings.TrimSpace(help)), "\n") }
}

// WithParams names the command's parameters in order, excluding the leading
// context.Context parameter. Go functions carry no parameter names at run
// time, so without this option the parameters are named arg0, arg1 and so
// on. Registration fails when the number of names differs from the number of
// parameters, or when a name is empty or repeated.
func WithParams(names ...string) Option {
	return func(o *options) { o.names = names }
}

// WithArgument sets the type identity of the parameter called name, for
// identities that the parameter's Go type does not determine on its own,
// such as [Choice]. The parameter's Go type must be the one the identity
// binds to. It is the counterpart of mitmproxy's command.argument decorator.
func WithArgument(name string, t Type) Option {
	return func(o *options) { o.overrides = append(o.overrides, argumentOverride{name: name, typ: t}) }
}

// WithDefault supplies the native value used when the parameter named name is
// omitted from a native or string call. Defaults must be assignable to the Go
// parameter types and cover trailing fixed parameters; a variadic parameter
// cannot have a default. Registration refuses invalid defaults with [ErrSignature].
// Supplied string arguments are parsed before defaults are applied, as upstream's
// bind/apply_defaults does. Signature help continues to show parameter names only.
func WithDefault(name string, value any) Option {
	return func(o *options) {
		if o.defaults == nil {
			o.defaults = make(map[string]any)
		}
		o.defaults[name] = value
	}
}

var (
	contextType = reflect.TypeFor[context.Context]()
	errorType   = reflect.TypeFor[error]()
)

// newCommand builds a Command from fn, checking its signature.
func newCommand(name string, fn any, opts ...Option) (*Command, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: empty command name", ErrSignature)
	}
	fv := reflect.ValueOf(fn)
	if fv.Kind() != reflect.Func || fv.IsNil() {
		return nil, fmt.Errorf("%w: command %s: %T is not a function", ErrSignature, name, fn)
	}
	ft := fv.Type()

	var o options
	for _, opt := range opts {
		opt(&o)
	}

	c := &Command{Name: name, Help: o.help, fn: fv}

	if ft.NumIn() == 0 || ft.In(0) != contextType {
		return nil, fmt.Errorf("%w: command %s: the first parameter must be a context.Context, which carries the dispatch frame, got %v", ErrSignature, name, ft)
	}
	const first = 1
	n := ft.NumIn() - first
	if o.names != nil && len(o.names) != n {
		return nil, fmt.Errorf("%w: command %s: %d parameter names for %d parameters", ErrSignature, name, len(o.names), n)
	}

	c.Params = make([]Param, n)
	index := make(map[string]int, n)
	for i := range n {
		pname := fmt.Sprintf("arg%d", i)
		if o.names != nil {
			pname = o.names[i]
		}
		if pname == "" {
			return nil, fmt.Errorf("%w: command %s: parameter %d has an empty name", ErrSignature, name, i)
		}
		if _, dup := index[pname]; dup {
			return nil, fmt.Errorf("%w: command %s: parameter name %q is repeated", ErrSignature, name, pname)
		}
		index[pname] = i
		c.Params[i] = Param{Name: pname, Variadic: ft.IsVariadic() && i == n-1}
	}

	// Explicit identities replace the ones derived from the Go types, so they
	// are applied first and the derived identity is looked up only for the
	// parameters left without one.
	for _, ov := range o.overrides {
		i, ok := index[ov.name]
		if !ok {
			return nil, fmt.Errorf("%w: command %s: no parameter named %q", ErrSignature, name, ov.name)
		}
		if ov.typ == nil {
			return nil, fmt.Errorf("%w: command %s: nil type for parameter %s", ErrSignature, name, ov.name)
		}
		pt := paramGoType(ft, first+i, c.Params[i].Variadic)
		if want := goTypeOf(ov.typ); want == nil || want != pt {
			return nil, fmt.Errorf("%w: command %s: parameter %s has Go type %v, which cannot carry type %s", ErrSignature, name, ov.name, pt, ov.typ.Name())
		}
		c.Params[i].Type = ov.typ
	}
	for i := range c.Params {
		if c.Params[i].Type != nil {
			continue
		}
		pt := paramGoType(ft, first+i, c.Params[i].Variadic)
		t, err := TypeFor(pt)
		if err != nil {
			return nil, fmt.Errorf("command %s: argument %s has an unknown type: %w", name, c.Params[i].Name, err)
		}
		c.Params[i].Type = t
	}

	c.required = n
	if ft.IsVariadic() {
		c.required--
	}
	if len(o.defaults) > 0 {
		c.defaults = make([]reflect.Value, n)
		for pname, value := range o.defaults {
			i, ok := index[pname]
			if !ok {
				return nil, fmt.Errorf("%w: command %s: no parameter named %q", ErrSignature, name, pname)
			}
			if c.Params[i].Variadic {
				return nil, fmt.Errorf("%w: command %s: variadic parameter %s cannot have a default", ErrSignature, name, pname)
			}
			v, err := argValue(value, ft.In(first+i))
			if err != nil {
				return nil, fmt.Errorf("%w: command %s: default for %s: %w", ErrSignature, name, pname, err)
			}
			c.defaults[i] = v
		}
		for i, p := range c.Params {
			if p.Variadic {
				break
			}
			if c.defaults[i].IsValid() {
				c.required = min(c.required, i)
			} else if i >= c.required {
				return nil, fmt.Errorf("%w: command %s: required parameter %s follows a default", ErrSignature, name, p.Name)
			}
		}
	}

	if err := c.setReturn(ft); err != nil {
		return nil, fmt.Errorf("command %s: %w", name, err)
	}
	return c, nil
}

// paramGoType returns the Go type of the in-th parameter of ft, or its
// element type when the parameter is variadic.
func paramGoType(ft reflect.Type, in int, variadic bool) reflect.Type {
	if variadic {
		return ft.In(in).Elem()
	}
	return ft.In(in)
}

// setReturn derives the command's result identity. A function may return
// nothing, an error, a value, or a value and an error.
func (c *Command) setReturn(ft reflect.Type) error {
	switch ft.NumOut() {
	case 0:
		return nil
	case 1:
		if ft.Out(0) == errorType {
			c.hasErr = true
			return nil
		}
	case 2:
		if ft.Out(1) != errorType {
			return fmt.Errorf("%w: second result must be error, not %v", ErrSignature, ft.Out(1))
		}
		c.hasErr = true
	default:
		return fmt.Errorf("%w: %d results; want at most a value and an error", ErrSignature, ft.NumOut())
	}
	t, err := TypeFor(ft.Out(0))
	if err != nil {
		return fmt.Errorf("return type has an unknown type: %w", err)
	}
	c.Return = t
	c.hasValue = true
	return nil
}

// call invokes the command with native Go arguments, checking their number
// and types first so that a mismatch is an error instead of a panic.
func (c *Command) call(ctx context.Context, args []any) (any, error) {
	ft := c.fn.Type()
	n := len(c.Params)
	variadic := n > 0 && c.Params[n-1].Variadic
	if len(args) < c.required || (!variadic && len(args) > n) {
		return nil, fmt.Errorf("%w: %s takes %s, got %d", ErrArgumentMismatch, c.Name, arity(n, c.required, variadic), len(args))
	}

	const first = 1
	in := make([]reflect.Value, 0, max(len(args), n)+first)
	// Manager.Call refuses a nil ctx, but a Runner hands run a context of
	// its own. Going through a pointer keeps the parameter's interface type,
	// so even a nil one is a valid Value rather than a reflect panic.
	in = append(in, reflect.ValueOf(&ctx).Elem())
	for i, arg := range args {
		pi := min(i, n-1)
		pt := paramGoType(ft, first+pi, variadic && pi == n-1)
		v, err := argValue(arg, pt)
		if err != nil {
			return nil, fmt.Errorf("%w: %s argument %s: %w", ErrArgumentMismatch, c.Name, c.Params[pi].Name, err)
		}
		in = append(in, v)
	}

	for i := len(args); i < n && !c.Params[i].Variadic; i++ {
		in = append(in, c.defaults[i])
	}

	out := c.fn.Call(in)
	var (
		ret any
		err error
	)
	if c.hasValue {
		ret = out[0].Interface()
	}
	if c.hasErr {
		if e := out[len(out)-1]; !e.IsNil() {
			err = e.Interface().(error)
		}
	}
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// argValue converts arg to a reflect.Value usable as a parameter of type pt.
func argValue(arg any, pt reflect.Type) (reflect.Value, error) {
	if arg == nil {
		switch pt.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			return reflect.Zero(pt), nil
		default:
			return reflect.Value{}, fmt.Errorf("nil is not a %v", pt)
		}
	}
	v := reflect.ValueOf(arg)
	if !v.Type().AssignableTo(pt) {
		return reflect.Value{}, fmt.Errorf("%T is not a %v", arg, pt)
	}
	return v, nil
}

// arity describes how many arguments a command takes.
func arity(n, required int, variadic bool) string {
	switch {
	case variadic:
		return fmt.Sprintf("at least %d arguments", required)
	case required < n:
		return fmt.Sprintf("between %d and %d arguments", required, n)
	case n == 1:
		return "1 argument"
	default:
		return fmt.Sprintf("%d arguments", n)
	}
}

// Runner runs a command call on behalf of [Manager.Call]. It must call run
// exactly once, with the context the command is to receive, and return
// run's results. name is the name the command was called by.
type Runner func(ctx context.Context, name string, run func(ctx context.Context) (any, error)) (any, error)

// Manager holds the registered commands. It is safe for concurrent use.
type Manager struct {
	mu       sync.RWMutex
	commands omap.Map[*Command]
	runner   Runner
}

// NewManager returns an empty Manager.
func NewManager() *Manager {
	return &Manager{}
}

// Register checks the signature of fn and registers it under name.
//
// fn must be a function whose first parameter is a context.Context; a
// function without one is refused with an error wrapping [ErrSignature] that
// names the command. That parameter receives the context passed to
// [Manager.Call], which carries the dispatch frame the command runs under,
// and is not a command parameter: a command that changes an option, calls
// another command or fires a hook must pass it on, or it waits forever for
// the dispatch lock its own caller holds. Every other parameter type, and
// the result type, must map to a command type identity (see [TypeFor]); a
// variadic final parameter maps on its element type. fn may return nothing,
// an error, a value, or a value and an error.
//
// Unlike mitmproxy, which silently replaces a command registered twice,
// Register refuses a name that is already taken, so that two addons claiming
// the same command are reported instead of one shadowing the other.
func (m *Manager) Register(name string, fn any, opts ...Option) error {
	c, err := newCommand(name, fn, opts...)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.commands.Has(name) {
		return fmt.Errorf("%w: %s", ErrDuplicateCommand, name)
	}
	m.commands.Set(name, c)
	return nil
}

// SetRunner makes [Manager.Call] run every command through r. A Manager
// without a Runner runs commands directly on the caller's goroutine, which
// is the default.
//
// SetRunner is for [github.com/zchee/mitmproxy-go/addon.NewManager], which
// installs a Runner that runs each command under the addon dispatch lock as
// a synchronous call. A Manager therefore serves one addon manager: a
// Runner, once installed, stays, and a later SetRunner, with another Runner
// or with nil, is refused with an error wrapping [ErrRunnerSet], because
// replacing it would run the commands under another lock or under none.
func (m *Manager) SetRunner(r Runner) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.runner != nil {
		return ErrRunnerSet
	}
	m.runner = r
	return nil
}

// Unregister removes the command registered under name and reports whether
// there was one. The addon manager uses it to take an addon's commands away
// when the addon is removed, so that loading the addon again can register
// them again.
func (m *Manager) Unregister(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.commands.Pop(name)
	return ok
}

// Call invokes the command registered under name with native Go arguments
// and returns its result, which is nil for a command that returns nothing.
//
// ctx is passed to the command as its first argument and must not be nil:
// the Runner an addon manager installs derives the command's context from
// it. A nil ctx is refused with an error wrapping [ErrArgumentMismatch],
// before the Runner or the command runs. The Manager's lock is not held
// while the command runs, so a command may call other commands.
//
// Every call goes through the [Runner] installed with [Manager.SetRunner],
// and the command is looked up inside it. A Manager that an addon manager
// was created with has the addon manager's Runner, so every entry point
// runs the command the same way: Call itself, whether from a frontend
// goroutine, from a hook with the hook's context or from another command
// with that command's context, and
// [github.com/zchee/mitmproxy-go/addon.Manager.Call] and
// [github.com/zchee/mitmproxy-go/master.Master.Call], which call it. The
// command runs under the addon dispatch lock, re-entering the hold of the
// caller when ctx carries a dispatch frame and taking the lock otherwise, as
// a synchronous call: like a mitmproxy command, it cannot yield, and
// [github.com/zchee/mitmproxy-go/addon.Concurrent] called with its context
// returns an error. A hook or a command must therefore pass on its own
// context; a context without its frame waits for the lock the caller holds.
// A Manager without a Runner runs the command directly on the caller's
// goroutine, without any lock.
func (m *Manager) Call(ctx context.Context, name string, args ...any) (any, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: %s: nil context", ErrArgumentMismatch, name)
	}
	run := func(ctx context.Context) (any, error) {
		m.mu.RLock()
		c, ok := m.commands.Get(name)
		m.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownCommand, name)
		}
		return c.call(ctx, args)
	}
	m.mu.RLock()
	r := m.runner
	m.mu.RUnlock()
	if r == nil {
		return run(ctx)
	}
	return r(ctx, name, run)
}

// Commands returns an iterator over the registered commands in registration
// order. It iterates over a snapshot taken when iteration starts.
func (m *Manager) Commands() iter.Seq2[string, *Command] {
	return func(yield func(string, *Command) bool) {
		m.mu.RLock()
		snapshot := m.commands.Clone()
		m.mu.RUnlock()
		for name, c := range snapshot.All() {
			if !yield(name, c) {
				return
			}
		}
	}
}
