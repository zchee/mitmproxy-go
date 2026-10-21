// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"errors"
	"fmt"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"

	"github.com/zchee/mitmproxy-go/addon"
)

const invocationKey = "mitmproxy.invocation"

type invocation struct {
	ctx     context.Context
	graph   *capabilities
	active  bool
	logging bool
}

func (i *invocation) check() error {
	if !i.active || i.graph.entry.owner.current.Load() != i {
		return errors.New("script invocation handle has expired")
	}
	return i.ctx.Err()
}

type capabilities struct {
	entry   *scriptEntry
	retired bool // accessed only by ordinary evaluations under dispatch
}

func (i *invocation) modelCheck() error {
	if _, err := i.graph.scope(); err != nil {
		return err
	}
	if i.graph.retired {
		return errors.New("script model handle belongs to a retired instance")
	}
	return nil
}

type moduleAddon struct {
	entry           *scriptEntry
	graph           *capabilities
	members         starlark.StringDict
	module          *starlarkstruct.Module
	name            string
	children        []*moduleAddon
	loaded          bool
	retired         bool
	scriptConfigure uint64
	logAdapter      *logAddon
}

type logAddon struct{ *moduleAddon }

func (m *moduleAddon) addon() any {
	if m.members["add_log"] == nil {
		return m
	}
	if m.logAdapter == nil {
		m.logAdapter = &logAddon{moduleAddon: m}
	}
	return m.logAdapter
}

func (m *moduleAddon) Name() string { return m.name }
func (m *moduleAddon) Addons() []any {
	out := make([]any, len(m.children))
	for n, c := range m.children {
		out[n] = c.addon()
	}
	return out
}

func (l *Loader) initialize(ctx context.Context, e *scriptEntry, data []byte) (*moduleAddon, error) {
	graph := &capabilities{entry: e}
	predeclared := graph.predeclared()
	_, program, err := starlark.SourceProgramOptions(&syntax.FileOptions{}, e.fullpath, data, predeclared.Has)
	if err != nil {
		return nil, err
	}
	var globals starlark.StringDict
	err = graph.evaluate(ctx, "init", func(thread *starlark.Thread, _ *invocation) error {
		var err error
		globals, err = program.Init(thread, predeclared)
		return err
	})
	if err != nil {
		return nil, err
	}
	m := &moduleAddon{entry: e, graph: graph, members: globals, name: "script:" + e.fullpath}
	if err := validateTree(globals); err != nil {
		return nil, err
	}
	return m, nil
}

func (g *capabilities) evaluate(ctx context.Context, name string, fn func(*starlark.Thread, *invocation) error) error {
	owner := g.entry.owner
	owner.mu.Lock()
	if owner.closed.Load() {
		owner.mu.Unlock()
		return errors.New("script loader is closed")
	}
	owner.wg.Add(1)
	owner.mu.Unlock()
	defer owner.wg.Done()
	ctx, cancel := context.WithCancel(ctx)
	stopLoader := context.AfterFunc(g.entry.owner.ctx, cancel)
	defer func() { stopLoader(); cancel() }()
	i := &invocation{ctx: ctx, graph: g, active: true, logging: name == "add_log"}
	prior := owner.current.Swap(i)
	defer func() {
		if i.active {
			owner.current.Store(prior)
		}
		i.active = false
	}()
	thread := &starlark.Thread{Name: g.entry.path + ":" + name}
	thread.SetLocal(invocationKey, i)
	thread.Load = func(_ *starlark.Thread, path string) (starlark.StringDict, error) {
		return nil, fmt.Errorf("module imports are unsupported: %q; use predeclared libraries", path)
	}
	thread.Print = func(_ *starlark.Thread, text string) {
		if !i.logging {
			g.entry.owner.logger().InfoContext(i.ctx, text)
		}
	}
	if budget := g.entry.owner.master.Options.Int("script_max_steps"); budget > 0 {
		thread.SetMaxExecutionSteps(uint64(budget))
	}
	stop := context.AfterFunc(ctx, func() { thread.Cancel("script invocation canceled") })
	defer stop()
	return fn(thread, i)
}

func diagnostic(err error) string {
	if eval, ok := errors.AsType[*starlark.EvalError](err); ok {
		return eval.Backtrace()
	}
	return err.Error()
}

func (m *moduleAddon) call(ctx context.Context, name string, arg func(*invocation) (starlark.Tuple, error)) error {
	if name != "done" {
		if m.retired || m.entry.owner.stopping.Load() {
			return errors.New("script instance is retired")
		}
		if m.loaded {
			if err := m.checkTree(); err != nil {
				return err
			}
		}
	}
	value := m.members[name]
	if value == nil {
		return nil
	}
	fn, ok := value.(starlark.Callable)
	if !ok {
		return fmt.Errorf("%s: %s is not callable", m.name, name)
	}
	err := m.graph.evaluate(ctx, name, func(thread *starlark.Thread, i *invocation) error {
		args, err := arg(i)
		if err != nil {
			return err
		}
		_, err = starlark.Call(thread, fn, args, nil)
		return err
	})
	if err != nil {
		return fmt.Errorf("%s: %s", m.name, diagnostic(err))
	}
	return nil
}

func noArgs(*invocation) (starlark.Tuple, error) { return nil, nil }

func (m *moduleAddon) Load(ctx context.Context, loader *addon.Loader) error {
	if err := m.call(ctx, "on_load", func(i *invocation) (starlark.Tuple, error) { return starlark.Tuple{loaderValue(i, loader, m)}, nil }); err != nil {
		return err
	}
	if err := validateTree(m.members); err != nil {
		return err
	}
	m.children = buildChildren(m, m.members)
	m.loaded = true
	return nil
}

func (m *moduleAddon) Configure(ctx context.Context, updated map[string]struct{}) error {
	if _, changed := updated["scripts"]; changed {
		generation := m.entry.owner.configureGeneration
		if generation != 0 && m.scriptConfigure == generation {
			return nil
		}
		m.scriptConfigure = generation
	}
	return m.call(ctx, "configure", func(i *invocation) (starlark.Tuple, error) {
		set := starlark.NewSet(len(updated))
		for name := range updated {
			if err := set.Insert(starlark.String(name)); err != nil {
				return nil, err
			}
		}
		set.Freeze()
		return starlark.Tuple{set}, nil
	})
}
func (m *moduleAddon) Running(ctx context.Context) error { return m.call(ctx, "running", noArgs) }
func (m *moduleAddon) Done(ctx context.Context) error {
	if m.retired {
		return nil
	}
	defer func() { m.retired = true; m.graph.retired = true }()
	return m.call(ctx, "done", noArgs)
}

func childrenOf(members starlark.StringDict) ([]*starlarkstruct.Module, error) {
	value := members["addons"]
	if value == nil {
		return nil, nil
	}
	list, ok := value.(*starlark.List)
	if !ok {
		return nil, errors.New("addons must be a list of module values")
	}
	if list.Len() > 1024 {
		return nil, errors.New("addons exceeds 1024 child modules")
	}
	out := make([]*starlarkstruct.Module, list.Len())
	for n := range list.Len() {
		mod, ok := list.Index(n).(*starlarkstruct.Module)
		if !ok {
			return nil, fmt.Errorf("addons[%d] must be a module", n)
		}
		out[n] = mod
	}
	return out, nil
}

func validateTree(members starlark.StringDict) error {
	count := 0
	active := make(map[*starlarkstruct.Module]bool)
	var walk func(starlark.StringDict, int) error
	walk = func(members starlark.StringDict, depth int) error {
		if depth > 32 {
			return errors.New("addons exceeds depth 32")
		}
		children, err := childrenOf(members)
		if err != nil {
			return err
		}
		for _, child := range children {
			count++
			if count > 1024 {
				return errors.New("addons exceeds 1024 child modules")
			}
			if active[child] {
				return errors.New("addons contains a cycle")
			}
			active[child] = true
			if err := walk(child.Members, depth+1); err != nil {
				return err
			}
			delete(active, child)
		}
		return nil
	}
	return walk(members, 0)
}

func buildChildren(parent *moduleAddon, members starlark.StringDict) []*moduleAddon {
	children, _ := childrenOf(members) // validated before construction
	out := make([]*moduleAddon, len(children))
	for n, child := range children {
		out[n] = &moduleAddon{entry: parent.entry, graph: parent.graph, members: child.Members, module: child, name: fmt.Sprintf("%s/%d:%s", parent.name, n, child.Name)}
	}
	return out
}

func (m *moduleAddon) checkTree() error {
	if err := validateTree(m.members); err != nil {
		return err
	}
	var check func(*moduleAddon) error
	check = func(node *moduleAddon) error {
		children, err := childrenOf(node.members)
		if err != nil {
			return err
		}
		if len(children) != len(node.children) {
			return fmt.Errorf("%s: addons topology changed after load", node.name)
		}
		for n, child := range children {
			if child != node.children[n].module {
				return fmt.Errorf("%s: addons[%d] topology changed after load", node.name, n)
			}
			if err := check(node.children[n]); err != nil {
				return err
			}
		}
		return nil
	}
	return check(m)
}
