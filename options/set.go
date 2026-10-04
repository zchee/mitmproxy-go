// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package options

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// Unparsed holds the raw values of a deferred "--set" specification whose
// option was not registered yet. They are parsed with the option's type when
// [Manager.ProcessDeferred] finds the option.
type Unparsed []string

// Set applies "--set" specifications of the form "name=value" or "name".
//
// Specifications naming the same option are grouped: a [TypeSeq] option
// receives every value in order, any other type rejects more than one value.
// A bare "name" means true for a [TypeBool] option, None for the optional
// types and an empty sequence for [TypeSeq]; "name=toggle" flips a bool.
// Set returns an [*OptionsError] when a value does not parse or when a name
// is not registered; nothing is applied in either case.
func (m *Manager) Set(ctx context.Context, specs ...string) error { return m.set(ctx, false, specs) }

// SetDeferred is [Manager.Set], except that specifications naming options
// that are not registered yet are kept and applied by
// [Manager.ProcessDeferred] once the options exist.
func (m *Manager) SetDeferred(ctx context.Context, specs ...string) error {
	return m.set(ctx, true, specs)
}

func (m *Manager) set(ctx context.Context, deferUnknown bool, specs []string) error {
	// Group the values by option name, keeping first-seen order for the
	// error message.
	var names []string
	grouped := make(map[string][]string)
	for _, spec := range specs {
		name, value, hasValue := strings.Cut(spec, "=")
		vals, seen := grouped[name]
		if !seen {
			names = append(names, name)
			vals = []string{}
		}
		if hasValue {
			vals = append(vals, value)
		}
		grouped[name] = vals
	}

	processed := make(map[string]any)
	var unknown []string
	m.mu.Lock()
	for _, name := range names {
		o, ok := m.opts.Get(name)
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		v, err := parseSetVal(o, grouped[name])
		if err != nil {
			m.mu.Unlock()
			return err
		}
		processed[name] = v
	}
	if deferUnknown {
		for _, name := range unknown {
			m.deferred.Set(name, Unparsed(grouped[name]))
		}
	}
	m.mu.Unlock()

	if !deferUnknown && len(unknown) > 0 {
		return Errorf("Unknown option(s): %s", strings.Join(unknown, ", "))
	}
	return m.Update(ctx, processed)
}

// ParseSetVal converts the raw "--set" values for the option called name to
// a value of the option's type, with the rules described at [Manager.Set].
// It returns an [*UnknownOptionError] when the option is not registered.
func (m *Manager) ParseSetVal(name string, values []string) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.opts.Get(name)
	if !ok {
		return nil, &UnknownOptionError{Names: []string{name}}
	}
	return parseSetVal(o, values)
}

// parseSetVal is mitmproxy's OptManager._parse_setval. m.mu must be held,
// because "toggle" reads the current value.
func parseSetVal(o *option, values []string) (any, error) {
	if o.typ == TypeSeq {
		return cloneStrings(values), nil
	}
	if len(values) > 1 {
		return nil, Errorf("Received multiple values for %s: %s", o.name, pyListRepr(values))
	}
	optstr, present := "", false
	if len(values) == 1 {
		optstr, present = values[0], true
	}

	switch o.typ {
	case TypeStr:
		if !present {
			return nil, Errorf("Option is required: %s", o.name)
		}
		return optstr, nil
	case TypeOptStr:
		if !present {
			return (*string)(nil), nil
		}
		return &optstr, nil
	case TypeInt, TypeOptInt:
		// Python tests the string for truthiness, so "name=" behaves like a
		// bare "name".
		if optstr != "" {
			n, ok := pyInt(optstr)
			if !ok {
				return nil, Errorf("Failed to parse option %s: not an integer: %s", o.name, optstr)
			}
			if o.typ == TypeOptInt {
				return &n, nil
			}
			return n, nil
		}
		if o.typ == TypeInt {
			return nil, Errorf("Option is required: %s", o.name)
		}
		return (*int)(nil), nil
	case TypeBool:
		switch optstr {
		case "toggle":
			cur, _ := o.current().(bool)
			return !cur, nil
		case "", "true":
			return true, nil
		case "false":
			return false, nil
		}
		return nil, Errorf(`Failed to parse option %s: boolean must be "true", "false", or have the value omitted (a synonym for "true").`, o.name)
	}
	return nil, Errorf("Failed to parse option %s: unsupported option type: %s", o.name, o.typ)
}

// pyInt parses s the way Python's int(s) does for base 10: surrounding
// whitespace is ignored, an optional sign is allowed, and single underscores
// may separate digits.
func pyInt(s string) (int, bool) {
	s = strings.TrimSpace(s)
	digits := strings.TrimLeft(s, "+-")
	if len(s)-len(digits) > 1 || digits == "" || digits[0] == '_' || digits[len(digits)-1] == '_' || strings.Contains(digits, "__") {
		return 0, false
	}
	n, err := strconv.ParseInt(s[:len(s)-len(digits)]+strings.ReplaceAll(digits, "_", ""), 10, 0)
	if err != nil {
		return 0, false
	}
	return int(n), true
}

// ProcessDeferred applies the deferred values whose options have been
// registered since they were stored, and forgets them once applied.
func (m *Manager) ProcessDeferred(ctx context.Context) error {
	update := make(map[string]any)
	m.mu.Lock()
	for k, v := range m.deferred.All() {
		o, ok := m.opts.Get(k)
		if !ok {
			continue
		}
		if u, ok := v.(Unparsed); ok {
			pv, err := parseSetVal(o, u)
			if err != nil {
				m.mu.Unlock()
				return err
			}
			v = pv
		}
		update[k] = v
	}
	m.mu.Unlock()

	if err := m.Update(ctx, update); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range slices.Sorted(maps.Keys(update)) {
		m.deferred.Delete(k)
	}
	return nil
}
