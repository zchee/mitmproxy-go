// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"errors"
	"fmt"
	"slices"

	"go.starlark.net/starlark"

	"github.com/zchee/mitmproxy-go/httpmsg"
)

type headerValue struct {
	i     *invocation
	data  func() httpmsg.Headers
	apply func(httpmsg.Headers) error
	fold  bool
}

func (*headerValue) String() string         { return "<headers>" }
func (*headerValue) Type() string           { return "headers" }
func (*headerValue) Freeze()                {}
func (h *headerValue) Truth() starlark.Bool { return h.Len() != 0 }
func (*headerValue) Hash() (uint32, error)  { return 0, errors.New("unhashable: headers") }
func (h *headerValue) keys() []string {
	if h.i.modelCheck() != nil {
		return nil
	}
	if h.fold {
		return h.data().Keys()
	}
	var out []string
	for _, field := range h.data() {
		name := string(field.Name)
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}
func (h *headerValue) Len() int { return len(h.keys()) }
func (h *headerValue) values(name string) []string {
	if h.fold {
		return h.data().GetAll(name)
	}
	var out []string
	for _, field := range h.data() {
		if string(field.Name) == name {
			out = append(out, string(field.Value))
		}
	}
	return out
}

func (h *headerValue) Get(key starlark.Value) (starlark.Value, bool, error) {
	if err := h.i.modelCheck(); err != nil {
		return nil, false, err
	}
	name, err := stringValue(key)
	if err != nil {
		return nil, false, err
	}
	if h.fold {
		s, ok := h.data().Lookup(name)
		return starlark.String(s), ok, nil
	}
	values := h.values(name)
	if len(values) == 0 {
		return starlark.None, false, nil
	}
	return starlark.String(values[0]), true, nil
}

func (h *headerValue) SetKey(key, value starlark.Value) error {
	if err := h.i.modelCheck(); err != nil {
		return err
	}
	name, err := stringValue(key)
	if err != nil {
		return err
	}
	x, err := stringValue(value)
	if err != nil {
		return err
	}
	return h.setAll(name, []string{x})
}

func (h *headerValue) setAll(name string, values []string) error {
	data := h.data().Clone()
	if h.fold {
		data.SetAll(name, values)
		return h.apply(data)
	}
	out := make(httpmsg.Headers, 0, len(data)+len(values))
	inserted := false
	for _, field := range data {
		if string(field.Name) != name {
			out = append(out, field)
			continue
		}
		if !inserted {
			for _, value := range values {
				out = append(out, httpmsg.Field{Name: []byte(name), Value: []byte(value)})
			}
			inserted = true
		}
	}
	if !inserted {
		for _, value := range values {
			out = append(out, httpmsg.Field{Name: []byte(name), Value: []byte(value)})
		}
	}
	return h.apply(out)
}

func (h *headerValue) Iterate() starlark.Iterator {
	keys := h.keys()
	values := make([]starlark.Value, len(keys))
	for n, key := range keys {
		values[n] = starlark.String(key)
	}
	return starlark.NewList(values).Iterate()
}

func (*headerValue) AttrNames() []string {
	return []string{"get", "get_all", "set_all", "keys", "items", "pop", "fields"}
}

func (h *headerValue) Attr(name string) (starlark.Value, error) {
	if err := h.i.modelCheck(); err != nil {
		return nil, err
	}
	if name == "fields" {
		out := make([]starlark.Value, len(h.data()))
		for n, field := range h.data() {
			out[n] = starlark.Tuple{starlark.Bytes(field.Name), starlark.Bytes(field.Value)}
		}
		return starlark.Tuple(out), nil
	}
	if !slices.Contains(h.AttrNames(), name) {
		return nil, nil
	}
	return builtin("headers."+name, h.i.modelCheck, func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		switch name {
		case "get", "pop":
			var key string
			fallback := starlark.Value(starlark.None)
			if err := starlark.UnpackArgs(name, args, kwargs, "key", &key, "default?", &fallback); err != nil {
				return nil, err
			}
			value, ok, err := h.Get(starlark.String(key))
			if err != nil {
				return nil, err
			}
			if !ok {
				return fallback, nil
			}
			if name == "pop" {
				if err := h.setAll(key, nil); err != nil {
					return nil, err
				}
			}
			return value, nil
		case "get_all":
			var key string
			if err := starlark.UnpackArgs(name, args, kwargs, "key", &key); err != nil {
				return nil, err
			}
			return new(conversion).value(h.i, h.values(key), 0)
		case "set_all":
			var key string
			var value starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "key", &key, "values", &value); err != nil {
				return nil, err
			}
			values, err := stringList(value)
			if err != nil {
				return nil, err
			}
			return starlark.None, h.setAll(key, values)
		case "keys":
			if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
				return nil, err
			}
			return new(conversion).value(h.i, h.keys(), 0)
		case "items":
			multi := false
			if err := starlark.UnpackArgs(name, args, kwargs, "multi?", &multi); err != nil {
				return nil, err
			}
			var out []starlark.Value
			if multi {
				for _, field := range h.data() {
					out = append(out, starlark.Tuple{starlark.String(field.Name), starlark.String(field.Value)})
				}
			} else {
				for _, key := range h.keys() {
					value, _, err := h.Get(starlark.String(key))
					if err != nil {
						return nil, err
					}
					out = append(out, starlark.Tuple{starlark.String(key), value})
				}
			}
			return starlark.NewList(out), nil
		}
		return nil, fmt.Errorf("unknown headers operation %s", name)
	}), nil
}

func headersNative(value starlark.Value) (httpmsg.Headers, error) {
	if h, ok := value.(*headerValue); ok {
		if err := h.i.modelCheck(); err != nil {
			return nil, err
		}
		return h.data().Clone(), nil
	}
	if dict, ok := value.(*starlark.Dict); ok {
		if dict.Len() > conversionLimit {
			return nil, errors.New("too many header entries")
		}
		out := make(httpmsg.Headers, 0, dict.Len())
		for _, pair := range dict.Items() {
			key, err := stringValue(pair[0])
			if err != nil {
				return nil, err
			}
			value, err := stringValue(pair[1])
			if err != nil {
				return nil, err
			}
			out = append(out, httpmsg.Field{Name: []byte(key), Value: []byte(value)})
		}
		return out, nil
	}
	seq, ok := value.(starlark.Indexable)
	if !ok || seq.Len() > conversionLimit {
		return nil, errors.New("headers require a mapping or bounded field sequence")
	}
	out := make(httpmsg.Headers, seq.Len())
	for n := range seq.Len() {
		pair, ok := seq.Index(n).(starlark.Indexable)
		if !ok || pair.Len() != 2 {
			return nil, errors.New("header field requires a name/value pair")
		}
		for j := range 2 {
			var data []byte
			if b, ok := pair.Index(j).(starlark.Bytes); ok {
				data = []byte(b)
			} else {
				s, err := stringValue(pair.Index(j))
				if err != nil {
					return nil, err
				}
				data = []byte(s)
			}
			if j == 0 {
				out[n].Name = data
			} else {
				out[n].Value = data
			}
		}
	}
	return out, nil
}

func wrapHeaders(i *invocation, h *httpmsg.Headers) starlark.Value {
	return &headerValue{i: i, data: func() httpmsg.Headers { return *h }, apply: func(value httpmsg.Headers) error { *h = value; return nil }, fold: true}
}

func wrapPairs(i *invocation, get func() [][2]string, set func([][2]string)) starlark.Value {
	return &headerValue{i: i, data: func() httpmsg.Headers {
		pairs := get()
		out := make(httpmsg.Headers, len(pairs))
		for n, pair := range pairs {
			out[n] = httpmsg.Field{Name: []byte(pair[0]), Value: []byte(pair[1])}
		}
		return out
	}, apply: func(data httpmsg.Headers) error {
		pairs := make([][2]string, len(data))
		for n, field := range data {
			pairs[n] = [2]string{string(field.Name), string(field.Value)}
		}
		set(pairs)
		return nil
	}}
}
