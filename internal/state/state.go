// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package state holds the helpers every flow model uses to convert itself to
// and from mitmproxy's serialised state dictionaries.
//
// A state value is one of the types the flow file codec can carry: nil (for
// Python None), bool, int64, float64, string (Python str), []byte (Python
// bytes), []any (Python list or tuple) and *omap.Map[any] (Python dict). An
// integer that does not fit in an int64 is a *big.Int. Free-form state such
// as flow metadata keeps it and writes it back unchanged; the typed
// accessors refuse it, since the models hold integers as int64.
// Models build their state with [omap.NewWithCapacity] and read it back with
// a [Decoder], which consumes the dictionary key by key so that whatever is
// left afterwards is reported as unexpected, as upstream's set_state does.
package state

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"time"

	"github.com/zchee/mitmproxy-go/omap"
)

// Map is a serialised state dictionary.
type Map = omap.Map[any]

// NewMap returns an empty state dictionary with room for n keys.
func NewMap(n int) *Map {
	return omap.NewWithCapacity[any](n)
}

// Decoder reads typed values out of a state dictionary.
//
// Every accessor removes the key it reads. The first error sticks: later
// accessors return zero values and [Decoder.Finish] reports that error, so a
// set_state implementation can read all its fields in sequence and check for
// failure once at the end.
type Decoder struct {
	m    *Map
	typ  string
	err  error
	done bool
}

// NewDecoder returns a Decoder that consumes m on behalf of the type named
// typ, which appears in error messages.
func NewDecoder(m *Map, typ string) *Decoder {
	d := &Decoder{m: m, typ: typ}
	if m == nil {
		d.err = fmt.Errorf("%s.set_state: state is None, expected a dict", typ)
	}
	return d
}

// Err returns the first error the Decoder recorded, if any.
func (d *Decoder) Err() error {
	return d.err
}

// Fail records err unless an earlier error is already recorded.
func (d *Decoder) Fail(err error) {
	if d.err == nil && err != nil {
		d.err = fmt.Errorf("%s.set_state: %w", d.typ, err)
	}
}

// Has reports whether key is still present in the dictionary.
func (d *Decoder) Has(key string) bool {
	return d.err == nil && d.m.Has(key)
}

// Any removes key and returns its raw value. A missing key is an error.
func (d *Decoder) Any(key string) any {
	if d.err != nil {
		return nil
	}
	v, ok := d.m.Pop(key)
	if !ok {
		d.Fail(fmt.Errorf("missing field %q", key))
		return nil
	}
	return v
}

// conv applies f to the value under key, recording any error.
func conv[T any](d *Decoder, key string, f func(any) (T, error)) T {
	v := d.Any(key)
	if d.err != nil {
		var zero T
		return zero
	}
	t, err := f(v)
	if err != nil {
		d.Fail(fmt.Errorf("field %q: %w", key, err))
	}
	return t
}

// optional applies f to the value under key unless it is None.
func optional[T any](d *Decoder, key string, f func(any) (T, error)) *T {
	v := d.Any(key)
	if d.err != nil || v == nil {
		return nil
	}
	t, err := f(v)
	if err != nil {
		d.Fail(fmt.Errorf("field %q: %w", key, err))
		return nil
	}
	return &t
}

// String removes key and returns it as a Python str.
func (d *Decoder) String(key string) string { return conv(d, key, AsString) }

// OptString removes key and returns it as a Python str, or nil for None.
func (d *Decoder) OptString(key string) *string { return optional(d, key, AsString) }

// Bytes removes key and returns it as Python bytes. An empty value is
// returned as a non-nil empty slice, so that callers can keep nil for None.
func (d *Decoder) Bytes(key string) []byte { return conv(d, key, AsBytes) }

// OptBytes removes key and returns it as Python bytes, or nil for None.
func (d *Decoder) OptBytes(key string) []byte {
	if p := optional(d, key, AsBytes); p != nil {
		return *p
	}
	return nil
}

// Int removes key and returns it as an integer.
func (d *Decoder) Int(key string) int64 { return conv(d, key, AsInt) }

// OptInt removes key and returns it as an integer, or nil for None.
func (d *Decoder) OptInt(key string) *int64 { return optional(d, key, AsInt) }

// Float removes key and returns it as a float.
func (d *Decoder) Float(key string) float64 { return conv(d, key, AsFloat) }

// OptFloat removes key and returns it as a float, or nil for None.
func (d *Decoder) OptFloat(key string) *float64 { return optional(d, key, AsFloat) }

// Bool removes key and returns it as a bool.
func (d *Decoder) Bool(key string) bool { return conv(d, key, AsBool) }

// OptBool removes key and returns it as a bool, or nil for None.
func (d *Decoder) OptBool(key string) *bool { return optional(d, key, AsBool) }

// List removes key and returns it as a list.
func (d *Decoder) List(key string) []any { return conv(d, key, AsList) }

// Dict removes key and returns it as a dictionary.
func (d *Decoder) Dict(key string) *Map { return conv(d, key, AsDict) }

// OptDict removes key and returns it as a dictionary, or nil for None.
func (d *Decoder) OptDict(key string) *Map {
	if p := optional(d, key, AsDict); p != nil {
		return *p
	}
	return nil
}

// Finish returns the first recorded error, or an error naming the keys that
// were never read. It must be called once all fields have been read.
func (d *Decoder) Finish() error {
	if d.err != nil || d.done {
		return d.err
	}
	d.done = true
	if d.m.Len() > 0 {
		d.err = Unexpected(d.typ, d.m.Keys())
	}
	return d.err
}

// Unexpected returns the error upstream's set_state raises for leftover keys.
func Unexpected(typ string, keys []string) error {
	return fmt.Errorf("unexpected fields in %s.set_state: %v", typ, keys)
}

// AsString converts a state value to a Go string.
func AsString(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", typeError("str", v)
	}
	return s, nil
}

// AsBytes converts a state value to a byte slice that is never nil.
func AsBytes(v any) ([]byte, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, typeError("bytes", v)
	}
	if b == nil {
		b = []byte{}
	}
	return b, nil
}

// AsInt converts a state value to an integer. Floats are truncated toward
// zero, as Python's int() does when upstream's set_state coerces numeric
// fields. Like int(), it refuses NaN and the infinities; a float whose
// integer part does not fit in an int64 is refused too, since the models
// hold integers as int64.
func AsInt(v any) (int64, error) {
	switch n := v.(type) {
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	case float64:
		return floatToInt(n)
	case *big.Int:
		return 0, bigIntError(n)
	}
	return 0, typeError("int", v)
}

// bigIntError refuses an integer that only a *big.Int holds.
func bigIntError(n *big.Int) error {
	return fmt.Errorf("integer %s does not fit in 64 bits", n)
}

// floatToInt truncates f toward zero. The bounds are exact powers of two:
// float64(math.MaxInt64) rounds up to 2**63, which does not fit.
func floatToInt(f float64) (int64, error) {
	switch {
	case math.IsNaN(f):
		return 0, errors.New("cannot convert float NaN to integer")
	case math.IsInf(f, 0):
		return 0, errors.New("cannot convert float infinity to integer")
	case f < -(1<<63) || f >= 1<<63:
		i, _ := big.NewFloat(f).Int(nil)
		return 0, bigIntError(i)
	}
	return int64(f), nil
}

// AsFloat converts a state value to a float. Integers are accepted, as
// Python's float() does when upstream's set_state coerces numeric fields,
// except one beyond the int64 range, which no typed field holds.
func AsFloat(v any) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case int64:
		return float64(n), nil
	case int:
		return float64(n), nil
	case *big.Int:
		return 0, bigIntError(n)
	}
	return 0, typeError("float", v)
}

// AsBool converts a state value to a bool.
func AsBool(v any) (bool, error) {
	b, ok := v.(bool)
	if !ok {
		return false, typeError("bool", v)
	}
	return b, nil
}

// AsList converts a state value to a list. A nil []any is returned as an
// empty non-nil list.
func AsList(v any) ([]any, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, typeError("list", v)
	}
	if l == nil {
		l = []any{}
	}
	return l, nil
}

// AsDict converts a state value to a dictionary.
func AsDict(v any) (*Map, error) {
	m, ok := v.(*Map)
	if !ok || m == nil {
		return nil, typeError("dict", v)
	}
	return m, nil
}

// ListOf converts a state list with f applied to every element.
func ListOf[T any](v any, f func(any) (T, error)) ([]T, error) {
	l, err := AsList(v)
	if err != nil {
		return nil, err
	}
	out := make([]T, len(l))
	for i, e := range l {
		if out[i], err = f(e); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
	}
	return out, nil
}

// Tuple converts a state value to a list of exactly n elements.
func Tuple(v any, n int) ([]any, error) {
	l, err := AsList(v)
	if err != nil {
		return nil, err
	}
	if len(l) != n {
		return nil, fmt.Errorf("expected a tuple of %d items, got %d", n, len(l))
	}
	return l, nil
}

func typeError(want string, got any) error {
	return fmt.Errorf("expected %s, got %s", want, TypeName(got))
}

// TypeName returns the Python type name of a state value, for error messages.
func TypeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case int, int64, *big.Int:
		return "int"
	case float64:
		return "float"
	case string:
		return "str"
	case []byte:
		return "bytes"
	case []any:
		return "list"
	case *Map:
		return "dict"
	}
	return fmt.Sprintf("%T", v)
}

// Opt returns *p, or nil when p is nil. It turns an optional Go field into
// the state value for a Python attribute that may be None.
func Opt[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

// OptInt returns *p as int64, or nil when p is nil.
func OptInt[T ~int | ~int64 | ~uint16 | ~uint32](p *T) any {
	if p == nil {
		return nil
	}
	return int64(*p)
}

// OptBytes returns b, or an untyped nil when b is nil. Storing a nil []byte
// directly would produce a typed nil that encoders treat as empty bytes.
func OptBytes(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}

// Bytes returns b, or a non-nil empty slice when b is nil, for attributes
// that are never None.
func Bytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// OptDict returns m, or an untyped nil when m is nil.
func OptDict(m *Map) any {
	if m == nil {
		return nil
	}
	return m
}

// BytesList converts a list of byte strings to a state list.
func BytesList(bs [][]byte) []any {
	out := make([]any, len(bs))
	for i, b := range bs {
		out[i] = Bytes(b)
	}
	return out
}

// StringList converts a list of strings to a state list.
func StringList(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// Copy returns a deep copy of a state value, like Python's copy.deepcopy
// over the types a state dictionary can hold. Values of other types are
// returned as they are.
func Copy(v any) any {
	switch x := v.(type) {
	case []byte:
		if x == nil {
			return x
		}
		return slices.Clone(x)
	case []any:
		if x == nil {
			return x
		}
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = Copy(e)
		}
		return out
	case *big.Int:
		if x == nil {
			return x
		}
		return new(big.Int).Set(x)
	case *Map:
		return CopyMap(x)
	}
	return v
}

// CopyMap returns a deep copy of a state dictionary, byte-string keys
// included. CopyMap(nil) is nil.
func CopyMap(m *Map) *Map {
	if m == nil {
		return nil
	}
	out := NewMap(m.Len())
	for k, v := range m.All() {
		if m.IsBytesKey(k) {
			out.SetBytesKey(k, Copy(v))
		} else {
			out.Set(k, Copy(v))
		}
	}
	return out
}

// Now returns the current time as Unix seconds with a fractional part, the
// representation upstream uses for every timestamp (Python's time.time()).
func Now() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

// NewID returns a random RFC 9562 version 4 UUID in its canonical text form,
// as Python's str(uuid.uuid4()) does. Flows and connections use it as their
// identifier.
func NewID() string {
	var u [16]byte
	_, _ = rand.Read(u[:]) // crypto/rand.Read never returns an error.
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	const hex = "0123456789abcdef"
	var s [36]byte
	j := 0
	for i, b := range u {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			s[j] = '-'
			j++
		}
		s[j], s[j+1] = hex[b>>4], hex[b&0x0f]
		j += 2
	}
	return string(s[:])
}

// Equal reports whether two state values are equal under Python's ==.
//
// Dictionaries compare without regard to key order, and a byte-string key
// never equals a text key; lists compare element by element. Integers compare by value whether held as int, int64 or
// *big.Int, and equal floats of the same value. Bytes never equal strings,
// as in Python 3. Values of any other type are never equal.
func Equal(a, b any) bool {
	if n, ok := a.(int); ok {
		a = int64(n)
	}
	if n, ok := b.(int); ok {
		b = int64(n)
	}
	// A nil *big.Int is no integer; Dumps refuses it as well.
	if n, ok := a.(*big.Int); ok && n == nil {
		return false
	}
	if n, ok := b.(*big.Int); ok && n == nil {
		return false
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case int64:
		switch y := b.(type) {
		case int64:
			return x == y
		case float64:
			return float64(x) == y
		case *big.Int:
			return y.IsInt64() && y.Int64() == x
		}
		return false
	case float64:
		switch y := b.(type) {
		case float64:
			return x == y
		case int64:
			return x == float64(y)
		case *big.Int:
			return bigEqualFloat(y, x)
		}
		return false
	case *big.Int:
		switch y := b.(type) {
		case *big.Int:
			return x.Cmp(y) == 0
		case int64:
			return x.IsInt64() && x.Int64() == y
		case float64:
			return bigEqualFloat(x, y)
		}
		return false
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []byte:
		y, ok := b.([]byte)
		return ok && string(x) == string(y)
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !Equal(x[i], y[i]) {
				return false
			}
		}
		return true
	case *Map:
		y, ok := b.(*Map)
		if !ok || x.Len() != y.Len() {
			return false
		}
		for k, v := range x.All() {
			w, ok := y.Get(k)
			if !ok || x.IsBytesKey(k) != y.IsBytesKey(k) || !Equal(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

// bigEqualFloat compares an integer with a float exactly, as Python does.
func bigEqualFloat(i *big.Int, f float64) bool {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return false
	}
	return new(big.Float).SetInt(i).Cmp(big.NewFloat(f)) == 0
}
