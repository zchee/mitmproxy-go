// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"fmt"

	"go.starlark.net/starlark"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/options"
)

const (
	conversionLimit = 65536
	conversionDepth = 64
)

type conversion struct {
	entries int
	active  map[starlark.Value]bool
}

func (c *conversion) admit(depth, n int) error {
	if depth > conversionDepth {
		return fmt.Errorf("conversion exceeds depth %d (or contains a cycle)", conversionDepth)
	}
	if n < 0 || n > conversionLimit-c.entries {
		return fmt.Errorf("conversion exceeds %d container entries", conversionLimit)
	}
	c.entries += n
	return nil
}

func (c *conversion) native(v starlark.Value, depth int) (any, error) {
	if err := c.admit(depth, 0); err != nil {
		return nil, err
	}
	switch v := v.(type) {
	case starlark.NoneType:
		return nil, nil
	case starlark.Bool:
		return bool(v), nil
	case starlark.String:
		return string(v), nil
	case starlark.Bytes:
		return []byte(v), nil
	case starlark.Float:
		return float64(v), nil
	case starlark.Int:
		n, ok := v.Int64()
		if !ok {
			return nil, fmt.Errorf("integer exceeds signed 64-bit range")
		}
		return n, nil
	case *flowValue:
		if err := v.i.modelCheck(); err != nil {
			return nil, err
		}
		return v.f, nil
	case *starlark.List:
		if c.active == nil {
			c.active = make(map[starlark.Value]bool)
		}
		if c.active[v] {
			return nil, fmt.Errorf("conversion contains a cycle")
		}
		c.active[v] = true
		defer delete(c.active, v)
		if err := c.admit(depth, v.Len()); err != nil {
			return nil, err
		}
		out := make([]any, v.Len())
		for n := range v.Len() {
			x, err := c.native(v.Index(n), depth+1)
			if err != nil {
				return nil, err
			}
			out[n] = x
		}
		return out, nil
	case starlark.Tuple:
		if err := c.admit(depth, len(v)); err != nil {
			return nil, err
		}
		out := make([]any, len(v))
		for n, x := range v {
			var err error
			out[n], err = c.native(x, depth+1)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	case *starlark.Dict:
		if c.active == nil {
			c.active = make(map[starlark.Value]bool)
		}
		if c.active[v] {
			return nil, fmt.Errorf("conversion contains a cycle")
		}
		c.active[v] = true
		defer delete(c.active, v)
		if err := c.admit(depth, v.Len()); err != nil {
			return nil, err
		}
		out := state.NewMap(v.Len())
		for _, pair := range v.Items() {
			key, err := stringValue(pair[0])
			if err != nil {
				return nil, err
			}
			x, err := c.native(pair[1], depth+1)
			if err != nil {
				return nil, err
			}
			out.Set(key, x)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("cannot convert %s to a native value", v.Type())
	}
}

func (c *conversion) value(i *invocation, v any, depth int) (starlark.Value, error) {
	if err := c.admit(depth, 0); err != nil {
		return nil, err
	}
	switch v := v.(type) {
	case nil:
		return starlark.None, nil
	case bool:
		return starlark.Bool(v), nil
	case int:
		return starlark.MakeInt(v), nil
	case int64:
		return starlark.MakeInt64(v), nil
	case float64:
		return starlark.Float(v), nil
	case string:
		return starlark.String(v), nil
	case []byte:
		if v == nil {
			return starlark.None, nil
		}
		return starlark.Bytes(v), nil
	case *string:
		return optionalString(v), nil
	case *int:
		if v == nil {
			return starlark.None, nil
		}
		return starlark.MakeInt(*v), nil
	case flow.Flow:
		return wrapFlow(i, v), nil
	case command.Path:
		return starlark.String(v), nil
	case command.Cmd:
		return starlark.String(v), nil
	case command.CmdArgs:
		return starlark.String(v), nil
	case command.Marker:
		return starlark.String(v), nil
	case command.CutSpec:
		return c.value(i, []string(v), depth)
	case []string:
		if err := c.admit(depth, len(v)); err != nil {
			return nil, err
		}
		out := make([]starlark.Value, len(v))
		for n, s := range v {
			out[n] = starlark.String(s)
		}
		return starlark.NewList(out), nil
	case []flow.Flow:
		if err := c.admit(depth, len(v)); err != nil {
			return nil, err
		}
		out := make([]starlark.Value, len(v))
		for n, f := range v {
			out[n] = wrapFlow(i, f)
		}
		return starlark.NewList(out), nil
	case []any:
		if err := c.admit(depth, len(v)); err != nil {
			return nil, err
		}
		out := make([]starlark.Value, len(v))
		for n, x := range v {
			var err error
			out[n], err = c.value(i, x, depth+1)
			if err != nil {
				return nil, err
			}
		}
		return starlark.NewList(out), nil
	case command.Data:
		if err := c.admit(depth, len(v)); err != nil {
			return nil, err
		}
		out := make([]starlark.Value, len(v))
		for n, x := range v {
			var err error
			out[n], err = c.value(i, x, depth+1)
			if err != nil {
				return nil, err
			}
		}
		return starlark.NewList(out), nil
	case *state.Map:
		if v == nil {
			return starlark.None, nil
		}
		if err := c.admit(depth, v.Len()); err != nil {
			return nil, err
		}
		out := starlark.NewDict(v.Len())
		for key, x := range v.All() {
			value, err := c.value(i, x, depth+1)
			if err != nil {
				return nil, err
			}
			if err = out.SetKey(starlark.String(key), value); err != nil {
				return nil, err
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported native conversion: %T", v)
	}
}

func stringList(v starlark.Value) ([]string, error) {
	seq, ok := v.(starlark.Indexable)
	if !ok {
		return nil, fmt.Errorf("expected a string sequence, got %s", v.Type())
	}
	if seq.Len() > conversionLimit {
		return nil, fmt.Errorf("sequence exceeds %d entries", conversionLimit)
	}
	out := make([]string, seq.Len())
	for n := range seq.Len() {
		s, err := stringValue(seq.Index(n))
		if err != nil {
			return nil, err
		}
		out[n] = s
	}
	return out, nil
}

func optionNative(typ options.Type, v starlark.Value) (any, error) {
	switch typ {
	case options.TypeBool:
		return boolValue(v)
	case options.TypeInt:
		return intValue(v)
	case options.TypeStr:
		return stringValue(v)
	case options.TypeSeq:
		return stringList(v)
	case options.TypeOptStr:
		if v == starlark.None {
			return (*string)(nil), nil
		}
		s, err := stringValue(v)
		return &s, err
	case options.TypeOptInt:
		if v == starlark.None {
			return (*int)(nil), nil
		}
		n, err := intValue(v)
		return &n, err
	default:
		return nil, fmt.Errorf("unsupported option type %s", typ)
	}
}

func commandArgument(typ command.Type, v starlark.Value) (any, error) {
	switch typ.Name() {
	case "Bool":
		return boolValue(v)
	case "Int":
		return intValue(v)
	case "Bytes":
		return bytesValue(v)
	case "Str", "Choice":
		return stringValue(v)
	case "Path":
		s, err := stringValue(v)
		return command.Path(s), err
	case "Cmd":
		s, err := stringValue(v)
		return command.Cmd(s), err
	case "Arg":
		s, err := stringValue(v)
		return command.CmdArgs(s), err
	case "Marker":
		s, err := stringValue(v)
		return command.Marker(s), err
	case "StrSeq":
		return stringList(v)
	case "CutSpec":
		s, err := stringList(v)
		return command.CutSpec(s), err
	case "Flow":
		f, ok := v.(*flowValue)
		if !ok {
			return nil, fmt.Errorf("expected flow, got %s", v.Type())
		}
		if err := f.i.modelCheck(); err != nil {
			return nil, err
		}
		return f.f, nil
	case "Flows":
		seq, ok := v.(starlark.Indexable)
		if !ok {
			return nil, fmt.Errorf("expected flow sequence")
		}
		if seq.Len() > conversionLimit {
			return nil, fmt.Errorf("too many flows")
		}
		out := make([]flow.Flow, seq.Len())
		for n := range seq.Len() {
			f, ok := seq.Index(n).(*flowValue)
			if !ok {
				return nil, fmt.Errorf("expected flow at index %d", n)
			}
			if err := f.i.modelCheck(); err != nil {
				return nil, err
			}
			out[n] = f.f
		}
		return out, nil
	case "Data":
		x, err := new(conversion).native(v, 0)
		if err != nil {
			return nil, err
		}
		rows, ok := x.([]any)
		if !ok {
			return nil, fmt.Errorf("expected data rows")
		}
		out := make(command.Data, len(rows))
		for n, row := range rows {
			cells, ok := row.([]any)
			if !ok {
				return nil, fmt.Errorf("expected data row")
			}
			for _, cell := range cells {
				switch cell.(type) {
				case string, []byte:
				default:
					return nil, fmt.Errorf("data cells must be strings or bytes")
				}
			}
			out[n] = cells
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported command type %s", typ.Name())
	}
}
