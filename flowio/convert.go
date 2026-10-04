// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowio

import (
	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
	"github.com/zchee/mitmproxy-go/internal/state"
)

// fromTnetstring converts a decoded tnetstring value into a state value:
// dictionaries become *state.Map with their keys in file order and of the
// kind they were read with, lists are converted element by element, and
// scalars are kept. An integer beyond the int64 range stays a *big.Int:
// free-form state such as metadata keeps it, and the models refuse it in
// their typed fields.
func fromTnetstring(v any) any {
	switch x := v.(type) {
	case *tnetstring.Dict:
		m := state.NewMap(x.Len())
		for k, e := range x.All() {
			if x.IsBytesKey(k) {
				m.SetBytesKey(k, fromTnetstring(e))
			} else {
				m.Set(k, fromTnetstring(e))
			}
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = fromTnetstring(e)
		}
		return out
	}
	return v
}

// toTnetstring converts a state value into one tnetstring.Dumps accepts:
// state dictionaries become *tnetstring.Dict in the same key order and with
// the same key kinds, which the encoder then writes reversed as mitmproxy
// does. A nil *state.Map is written as None. Values of other types are
// passed through, so Dumps reports any that have no tnetstring form.
func toTnetstring(v any) any {
	switch x := v.(type) {
	case *state.Map:
		if x == nil {
			return nil
		}
		d := tnetstring.NewDict(x.Len())
		for k, e := range x.All() {
			if x.IsBytesKey(k) {
				d.SetBytesKey(k, toTnetstring(e))
			} else {
				d.Set(k, toTnetstring(e))
			}
		}
		return d
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = toTnetstring(e)
		}
		return out
	}
	return v
}
