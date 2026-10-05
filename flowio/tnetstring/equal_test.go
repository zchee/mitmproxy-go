// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tnetstring

import (
	"bytes"
	"math/big"

	"github.com/zchee/mitmproxy-go/omap"
)

// equal reports whether two decoded tnetstring values are the same value of
// the same type. It is type-strict, unlike Python's ==: an integer never
// equals a float (1 and 1.0 differ), and a text string never equals a byte
// string.
//
// Lists compare element by element; dictionaries hold the same keys, of the
// same kinds, with equal values, regardless of order; integers compare by
// numeric value whether held as int64 or *big.Int; floats compare with IEEE
// semantics, so a NaN is never equal to anything.
func equal(a, b any) bool {
	switch a := a.(type) {
	case nil:
		return b == nil
	case bool:
		b, ok := b.(bool)
		return ok && a == b
	case string:
		b, ok := b.(string)
		return ok && a == b
	case []byte:
		b, ok := b.([]byte)
		return ok && bytes.Equal(a, b)
	case float64:
		b, ok := b.(float64)
		return ok && a == b
	case int64:
		switch b := b.(type) {
		case int64:
			return a == b
		case *big.Int:
			return b.IsInt64() && b.Int64() == a
		}
		return false
	case *big.Int:
		switch b := b.(type) {
		case int64:
			return a.IsInt64() && a.Int64() == b
		case *big.Int:
			return a.Cmp(b) == 0
		}
		return false
	case []any:
		b, ok := b.([]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for i := range a {
			if !equal(a[i], b[i]) {
				return false
			}
		}
		return true
	case *omap.Map[any]:
		b, ok := b.(*omap.Map[any])
		return ok && dictEqual(a, b)
	}
	return false
}

func dictEqual(a, b *omap.Map[any]) bool {
	if a.Len() != b.Len() {
		return false
	}
	for k, av := range a.All() {
		bv, ok := b.Get(k)
		if !ok || a.IsBytesKey(k) != b.IsBytesKey(k) || !equal(av, bv) {
			return false
		}
	}
	return true
}
