// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/options"
)

func (g *capabilities) predeclared() starlark.StringDict {
	ctx := &object{kind: "ctx", check: g.check, names: []string{"log", "options", "master", "sleep", "http_get"}}
	log := &logValue{graph: g}
	opts := &object{kind: "options", check: g.check, names: g.entry.owner.master.Options.Keys()}
	opts.get = func(name string) (starlark.Value, error) {
		i := (*invocation)(nil)
		if !g.worker {
			var err error
			i, err = g.scope()
			if err != nil {
				return nil, err
			}
		}
		opt, ok := g.entry.owner.master.Options.Lookup(name)
		if !ok {
			return nil, nil
		}
		v, err := new(conversion).value(i, opt.Current(), 0)
		if err == nil {
			v.Freeze()
		}
		return v, err
	}
	opts.set = func(name string, v starlark.Value) error {
		opt, ok := g.entry.owner.master.Options.Lookup(name)
		if !ok {
			return fmt.Errorf("No such option: %s", name) //nolint:staticcheck // Preserve the upstream option-attribute diagnostic.
		}
		x, err := optionNative(opt.Type(), v)
		if err != nil {
			return err
		}
		update := func(ctx context.Context) error {
			return g.entry.owner.master.Options.Update(ctx, map[string]any{name: x})
		}
		if g.worker {
			return g.entry.owner.master.Do(g.entry.owner.ctx, update)
		}
		i, err := g.scope()
		if err != nil {
			return err
		}
		return update(i.ctx)
	}
	commands := &object{kind: "commands", check: g.check, names: []string{"call"}, get: func(name string) (starlark.Value, error) {
		if name == "call" {
			return starlark.NewBuiltin("ctx.master.commands.call", g.commandCall), nil
		}
		return nil, nil
	}}
	masterValue := &object{kind: "master", check: g.check, names: []string{"commands", "shutdown"}, get: func(name string) (starlark.Value, error) {
		switch name {
		case "commands":
			return commands, nil
		case "shutdown":
			return builtin("ctx.master.shutdown", g.check, func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				if err := starlark.UnpackArgs("ctx.master.shutdown", args, kwargs); err != nil {
					return nil, err
				}
				g.entry.owner.master.Shutdown()
				return starlark.None, nil
			}), nil
		}
		return nil, nil
	}}
	ctx.get = func(name string) (starlark.Value, error) {
		switch name {
		case "log":
			return log, nil
		case "options":
			return opts, nil
		case "master":
			return masterValue, nil
		case "sleep":
			return starlark.NewBuiltin("ctx.sleep", g.sleep), nil
		case "http_get":
			return starlark.NewBuiltin("ctx.http_get", g.httpGet), nil
		}
		return nil, nil
	}
	return starlark.StringDict{
		"concurrent": starlark.NewBuiltin("concurrent", concurrentBuiltin),
		"ctx":        ctx,
		"module":     starlark.NewBuiltin("module", starlarkstruct.MakeModule),
		"byteops": &starlarkstruct.Module{Name: "byteops", Members: starlark.StringDict{
			"replace":    starlark.NewBuiltin("byteops.replace", byteReplace),
			"startswith": starlark.NewBuiltin("byteops.startswith", byteStartsWith),
		}},
		"http": httpLibrary(g),
		"dns":  dnsLibrary(g),
	}
}

func (g *capabilities) sleep(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("ctx.sleep", args, kwargs, "seconds", &value); err != nil {
		return nil, err
	}
	seconds, ok := starlark.AsFloat(value)
	if !ok || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds >= float64(math.MaxInt64)/float64(time.Second) {
		return nil, errors.New("ctx.sleep requires a finite nonnegative representable duration")
	}
	i, err := threadInvocation(thread)
	if err != nil {
		return nil, err
	}
	err = i.blocking(func(ctx context.Context) error {
		if wait := g.entry.owner.sleepWait; wait != nil {
			return wait(ctx, time.Duration(seconds*float64(time.Second)))
		}
		timer := time.NewTimer(time.Duration(seconds * float64(time.Second)))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	})
	return starlark.None, err
}

func (g *capabilities) commandCall(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	i, err := threadInvocation(thread)
	if err != nil {
		return nil, err
	}
	if len(kwargs) != 0 || len(args) == 0 {
		return nil, errors.New("commands.call requires a name and positional arguments")
	}
	name, err := stringValue(args[0])
	if err != nil {
		return nil, err
	}
	var result starlark.Value
	err = i.shared(func(ctx context.Context) error {
		var registered *command.Command
		for key, candidate := range g.entry.owner.master.Commands.Commands() {
			if key == name {
				registered = candidate
				break
			}
		}
		if registered == nil {
			return fmt.Errorf("unknown command: %s", name)
		}
		values := args[1:]
		converted := make([]any, len(values))
		owned := new(commandOwnership)
		type argumentKey struct {
			list *starlark.List
			kind string
		}
		lists := make(map[argumentKey]any)
		for n, value := range values {
			param := n
			if param >= len(registered.Params) {
				if len(registered.Params) == 0 || !registered.Params[len(registered.Params)-1].Variadic {
					return fmt.Errorf("too many arguments for %s", name)
				}
				param = len(registered.Params) - 1
			}
			key := argumentKey{kind: registered.Params[param].Type.Name()}
			if i.worker {
				key.list, _ = value.(*starlark.List)
				if prior, ok := lists[key]; key.list != nil && ok {
					converted[n] = prior
					continue
				}
			}
			var err error
			converted[n], err = commandArgument(registered.Params[param].Type, value)
			if err != nil {
				return err
			}
			if i.worker {
				converted[n], err = owned.argument(converted[n], 0)
				if err != nil {
					return err
				}
				if key.list != nil {
					lists[key] = converted[n]
				}
			}
		}
		native, callErr := g.entry.owner.master.Commands.Call(ctx, name, converted...)
		if i.worker {
			if err := owned.copyBack(); err != nil {
				return errors.Join(callErr, err)
			}
			var err error
			native, err = new(commandOwnership).argument(native, 0)
			if err != nil {
				return err
			}
		}
		if callErr != nil {
			return callErr
		}
		var err error
		result, err = new(conversion).value(i, native, 0)
		return err
	})
	return result, err
}

type logValue struct{ graph *capabilities }

func (*logValue) String() string        { return "<ctx.log>" }
func (*logValue) Type() string          { return "log" }
func (*logValue) Name() string          { return "ctx.log" }
func (*logValue) Freeze()               {}
func (*logValue) Truth() starlark.Bool  { return true }
func (*logValue) Hash() (uint32, error) { return 0, errors.New("unhashable: log") }
func (*logValue) AttrNames() []string   { return []string{"debug", "info", "warn", "error", "alert"} }

func (v *logValue) CallInternal(thread *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return v.log(thread, slog.LevelInfo, args, kwargs)
}

func (v *logValue) Attr(name string) (starlark.Value, error) {
	levels := map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError, "alert": addon.LevelAlert}
	level, ok := levels[name]
	if !ok {
		return nil, nil
	}
	return builtin("ctx.log."+name, v.graph.check, func(thread *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return v.log(thread, level, args, kwargs)
	}), nil
}

func (v *logValue) log(thread *starlark.Thread, level slog.Level, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	i, err := threadInvocation(thread)
	if err != nil {
		return nil, err
	}
	var text string
	if err := starlark.UnpackArgs("ctx.log", args, kwargs, "message", &text); err != nil {
		return nil, err
	}
	if i.logging {
		return nil, errors.New("logging inside add_log is not supported")
	}
	err = i.shared(func(ctx context.Context) error {
		v.graph.entry.owner.logger().Log(ctx, level, text)
		return nil
	})
	return starlark.None, err
}

func loaderValue(i *invocation, loader *addon.Loader, m *moduleAddon) starlark.Value {
	return &object{kind: "loader", check: i.check, names: []string{"add_option", "add_command"}, get: func(name string) (starlark.Value, error) {
		switch name {
		case "add_option":
			return builtin("loader.add_option", i.check, func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var name, typeName, help string
				var def starlark.Value
				choices := starlark.Value(starlark.NewList(nil))
				if err := starlark.UnpackArgs("loader.add_option", args, kwargs, "name", &name, "type_name", &typeName, "default", &def, "help", &help, "choices?", &choices); err != nil {
					return nil, err
				}
				types := map[string]options.Type{"bool": options.TypeBool, "int": options.TypeInt, "str": options.TypeStr, "optional-int": options.TypeOptInt, "optional-str": options.TypeOptStr, "sequence-of-str": options.TypeSeq}
				typ, ok := types[typeName]
				if !ok {
					return nil, fmt.Errorf("unsupported option type: %s", typeName)
				}
				x, err := optionNative(typ, def)
				if err != nil {
					return nil, err
				}
				list, err := stringList(choices)
				if err != nil {
					return nil, err
				}
				return starlark.None, loader.AddOption(i.ctx, name, typ, x, help, list...)
			}), nil
		case "add_command":
			return builtin("loader.add_command", i.check, func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var name, help string
				var fn *starlark.Function
				if err := starlark.UnpackArgs("loader.add_command", args, kwargs, "name", &name, "function", &fn, "help?", &help); err != nil {
					return nil, err
				}
				if fn.NumParams() != 0 || fn.HasVarargs() || fn.HasKwargs() {
					return nil, errors.New("loader.add_command supports zero-argument functions only")
				}
				err := loader.AddCommand(name, func(ctx context.Context) error {
					if m.retired || m.entry.owner.stopping.Load() {
						return errors.New("script command instance is retired")
					}
					return m.graph.evaluate(ctx, name, func(thread *starlark.Thread, _ *invocation) error {
						_, err := starlark.Call(thread, fn, nil, nil)
						return err
					})
				}, command.WithHelp(help))
				return starlark.None, err
			}), nil
		}
		return nil, nil
	}}
}

func byteReplace(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data, old, replacement starlark.Bytes
	count := -1
	if err := starlark.UnpackArgs("byteops.replace", args, kwargs, "data", &data, "old", &old, "new", &replacement, "count?", &count); err != nil {
		return nil, err
	}
	return starlark.Bytes(bytes.Replace([]byte(data), []byte(old), []byte(replacement), count)), nil
}

func byteStartsWith(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data, prefix starlark.Bytes
	if err := starlark.UnpackArgs("byteops.startswith", args, kwargs, "data", &data, "prefix", &prefix); err != nil {
		return nil, err
	}
	return starlark.Bool(bytes.HasPrefix([]byte(data), []byte(prefix))), nil
}
