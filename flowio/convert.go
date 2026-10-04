// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowio

import (
	"fmt"
	"math/big"

	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
	"github.com/zchee/mitmproxy-go/internal/state"
)

// fromTnetstring converts a decoded tnetstring value into a state value:
// dictionaries become *state.Map with their keys in file order, lists are
// converted element by element, and scalars are kept. The flow models hold
// integers as int64, so an integer that only fits a *big.Int is an error.
func fromTnetstring(v any) (any, error) {
	switch x := v.(type) {
	case *tnetstring.Dict:
		m := state.NewMap(x.Len())
		for k, e := range x.All() {
			c, err := fromTnetstring(e)
			if err != nil {
				return nil, err
			}
			m.Set(k, c)
		}
		return m, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			c, err := fromTnetstring(e)
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	case *big.Int:
		return nil, fmt.Errorf("integer %s does not fit in 64 bits", x)
	}
	return v, nil
}

// toTnetstring converts a state value into one tnetstring.Dumps accepts:
// state dictionaries become *tnetstring.Dict in the same key order, which
// the encoder then writes reversed as mitmproxy does. A nil *state.Map is
// written as None. Values of other types are passed through, so Dumps
// reports any that have no tnetstring form.
func toTnetstring(v any) any {
	switch x := v.(type) {
	case *state.Map:
		if x == nil {
			return nil
		}
		d := tnetstring.NewDict(x.Len())
		for k, e := range x.All() {
			d.Set(k, toTnetstring(e))
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
