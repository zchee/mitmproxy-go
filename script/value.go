// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"errors"
	"fmt"
	"slices"

	"go.starlark.net/starlark"
)

// object exposes only an explicit field table. It never reflects arbitrary Go
// fields, methods, sockets or credentials into the scripting environment.
type object struct {
	kind  string
	names []string
	check func() error
	get   func(string) (starlark.Value, error)
	set   func(string, starlark.Value) error
}

func (o *object) String() string        { return "<" + o.kind + ">" }
func (o *object) Type() string          { return o.kind }
func (*object) Freeze()                 {}
func (*object) Truth() starlark.Bool    { return true }
func (o *object) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", o.kind) }
func (o *object) AttrNames() []string   { return slices.Clone(o.names) }
func (o *object) Attr(name string) (starlark.Value, error) {
	if o.check != nil {
		if err := o.check(); err != nil {
			return nil, err
		}
	}
	return o.get(name)
}

func (o *object) SetField(name string, value starlark.Value) error {
	if o.check != nil {
		if err := o.check(); err != nil {
			return err
		}
	}
	if o.set == nil {
		return fmt.Errorf("%s.%s is read-only", o.kind, name)
	}
	return o.set(name, value)
}

func threadInvocation(thread *starlark.Thread) (*invocation, error) {
	i, ok := thread.Local(invocationKey).(*invocation)
	if !ok {
		return nil, errors.New("no active script invocation")
	}
	if err := i.check(); err != nil {
		return nil, err
	}
	return i, nil
}

func (g *capabilities) scope() (*invocation, error) {
	current := g.entry.owner.current.Load()
	if current == nil {
		return nil, errors.New("no active ordinary script dispatch scope")
	}
	if current.graph != g {
		return nil, errors.New("model handle belongs to another script instance")
	}
	if err := current.check(); err != nil {
		return nil, err
	}
	return current, nil
}

func (g *capabilities) check() error {
	if g.worker {
		return g.entry.owner.ctx.Err()
	}
	_, err := g.scope()
	return err
}

func stringValue(v starlark.Value) (string, error) {
	s, ok := starlark.AsString(v)
	if !ok {
		return "", fmt.Errorf("expected string, got %s", v.Type())
	}
	return s, nil
}

func bytesValue(v starlark.Value) ([]byte, error) {
	b, ok := v.(starlark.Bytes)
	if !ok {
		return nil, fmt.Errorf("expected bytes, got %s", v.Type())
	}
	return []byte(b), nil
}

func intValue(v starlark.Value) (int, error) {
	i, ok := v.(starlark.Int)
	if !ok {
		return 0, fmt.Errorf("expected int, got %s", v.Type())
	}
	var n int
	if err := starlark.AsInt(i, &n); err != nil {
		return 0, err
	}
	return n, nil
}

func boolValue(v starlark.Value) (bool, error) {
	b, ok := v.(starlark.Bool)
	if !ok {
		return false, fmt.Errorf("expected bool, got %s", v.Type())
	}
	return bool(b), nil
}

func optionalString(s *string) starlark.Value {
	if s == nil {
		return starlark.None
	}
	return starlark.String(*s)
}

func optionalFloat(f *float64) starlark.Value {
	if f == nil {
		return starlark.None
	}
	return starlark.Float(*f)
}

func builtin(name string, check func() error, fn func(*starlark.Thread, starlark.Tuple, []starlark.Tuple) (starlark.Value, error)) *starlark.Builtin {
	return starlark.NewBuiltin(name, func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if check != nil {
			if err := check(); err != nil {
				return nil, err
			}
		}
		return fn(thread, args, kwargs)
	})
}

func actionBuiltin(name string, i *invocation, fn func() error) *starlark.Builtin {
	return builtin(name, i.modelCheck, func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		return starlark.None, fn()
	})
}
