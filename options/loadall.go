// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package options

import (
	"context"
	"path/filepath"
)

// LoadAll applies the option sources of a mitmproxy command line in
// upstream's order, so that later sources override earlier ones:
//
//  1. setSpecs, the "--set" specifications, with unknown names deferred;
//  2. config.yaml in confdir;
//  3. config.yml in confdir;
//  4. passedFlags, the dedicated command-line flags that were actually
//     passed, keyed by option name.
//
// The resulting precedence is: passed flags > config.yml > config.yaml >
// --set > defaults. A flag missing from passedFlags never overrides a
// configuration value; as in upstream, entries whose value is None (nil, or
// a nil *string or *int) or whose name is not a registered option are
// ignored.
//
// When confdir is empty, the current value of the "confdir" option is used
// (which a "--set confdir=..." specification may have changed), falling
// back to [ConfDir]. A leading "~" is expanded.
func (m *Manager) LoadAll(ctx context.Context, setSpecs []string, confdir string, passedFlags map[string]any) error {
	if err := m.SetDeferred(ctx, setSpecs...); err != nil {
		return err
	}
	if confdir == "" {
		confdir = ConfDir
		if o, ok := m.Lookup("confdir"); ok {
			if s, ok := o.Current().(string); ok {
				confdir = s
			}
		}
	}
	if err := m.LoadPaths(ctx, filepath.Join(confdir, "config.yaml"), filepath.Join(confdir, "config.yml")); err != nil {
		return err
	}
	flags := make(map[string]any, len(passedFlags))
	for k, v := range passedFlags {
		if !isNone(v) && m.Has(k) {
			flags[k] = v
		}
	}
	return m.Update(ctx, flags)
}

// isNone reports whether v is Python's None in any of the forms a caller may
// pass: untyped nil or a nil *string or *int.
func isNone(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case *string:
		return x == nil
	case *int:
		return x == nil
	}
	return false
}
