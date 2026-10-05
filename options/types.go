// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package options

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

// Type identifies the value type of an option.
//
// The set of types is the set of typespecs mitmproxy accepts for options:
// bool, int, str, Sequence[str], Optional[str] and Optional[int].
type Type uint8

// Option types. The zero value is not a valid type.
const (
	// TypeBool holds a bool.
	TypeBool Type = iota + 1
	// TypeInt holds an int.
	TypeInt
	// TypeStr holds a string.
	TypeStr
	// TypeSeq holds a []string (mitmproxy's Sequence[str]).
	TypeSeq
	// TypeOptStr holds a *string, nil meaning None (Optional[str]).
	TypeOptStr
	// TypeOptInt holds a *int, nil meaning None (Optional[int]).
	TypeOptInt
)

// String returns the type name mitmproxy prints for the type in option
// dumps and in the command type system.
func (t Type) String() string {
	switch t {
	case TypeBool:
		return "bool"
	case TypeInt:
		return "int"
	case TypeStr:
		return "str"
	case TypeSeq:
		return "sequence of str"
	case TypeOptStr:
		return "optional str"
	case TypeOptInt:
		return "optional int"
	default:
		return fmt.Sprintf("Type(%d)", uint8(t))
	}
}

// Value is the set of Go types an option value is stored as.
type Value interface {
	bool | int | string | []string | *string | *int
}

// coerce checks that v is acceptable for an option of type typ and returns
// it in its canonical Go representation, deep-copied so the caller keeps no
// alias into the stored value.
//
// Besides the canonical types it accepts the shapes a YAML decoder produces
// ([]any of strings, every Go integer kind) and untyped nil for the optional
// types, mirroring how mitmproxy's typecheck accepts any list or tuple of
// str for Sequence[str] and None for Optional[T].
func coerce(name string, typ Type, v any) (any, error) {
	switch typ {
	case TypeBool:
		if b, ok := v.(bool); ok {
			return b, nil
		}
	case TypeInt:
		if n, ok := toInt(v); ok {
			return n, nil
		}
	case TypeStr:
		if s, ok := v.(string); ok {
			return s, nil
		}
	case TypeSeq:
		switch s := v.(type) {
		case []string:
			return cloneStrings(s), nil
		case []any:
			out := make([]string, 0, len(s))
			for _, e := range s {
				es, ok := e.(string)
				if !ok {
					return nil, &TypeError{Name: name, Type: typ, Value: v}
				}
				out = append(out, es)
			}
			return out, nil
		}
	case TypeOptStr:
		switch s := v.(type) {
		case nil:
			return (*string)(nil), nil
		case string:
			return &s, nil
		case *string:
			if s == nil {
				return (*string)(nil), nil
			}
			c := *s
			return &c, nil
		}
	case TypeOptInt:
		switch n := v.(type) {
		case nil:
			return (*int)(nil), nil
		case *int:
			if n == nil {
				return (*int)(nil), nil
			}
			c := *n
			return &c, nil
		default:
			if i, ok := toInt(v); ok {
				return &i, nil
			}
		}
	}
	return nil, &TypeError{Name: name, Type: typ, Value: v}
}

// toInt converts any Go integer kind that fits into an int. Booleans and
// floats are rejected.
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int8:
		return int(n), true
	case int16:
		return int(n), true
	case int32:
		return int(n), true
	case int64:
		if n < math.MinInt || n > math.MaxInt {
			return 0, false
		}
		return int(n), true
	case uint:
		if n > math.MaxInt {
			return 0, false
		}
		return int(n), true
	case uint8:
		return int(n), true
	case uint16:
		return int(n), true
	case uint32:
		if uint64(n) > math.MaxInt {
			return 0, false
		}
		return int(n), true
	case uint64:
		if n > math.MaxInt {
			return 0, false
		}
		return int(n), true
	}
	return 0, false
}

// copyValue deep-copies a value in canonical representation so that callers
// cannot mutate stored option state through the returned value.
func copyValue(v any) any {
	switch x := v.(type) {
	case []string:
		return cloneStrings(x)
	case *string:
		if x == nil {
			return x
		}
		c := *x
		return &c
	case *int:
		if x == nil {
			return x
		}
		c := *x
		return &c
	}
	return v
}

// cloneStrings copies s into a new non-nil slice, so an empty sequence is
// always represented the same way regardless of how it was supplied.
func cloneStrings(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	return out
}

// equalValues reports whether two canonical values are equal, comparing
// pointers by their targets.
func equalValues(a, b any) bool {
	switch x := a.(type) {
	case []string:
		y, ok := b.([]string)
		return ok && slices.Equal(x, y)
	case *string:
		y, ok := b.(*string)
		if !ok || (x == nil) != (y == nil) {
			return false
		}
		return x == nil || *x == *y
	case *int:
		y, ok := b.(*int)
		if !ok || (x == nil) != (y == nil) {
			return false
		}
		return x == nil || *x == *y
	}
	return a == b
}

// pyListRepr formats ss the way Python's repr() formats a list of str.
func pyListRepr(ss []string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = pyrepr.Str(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
