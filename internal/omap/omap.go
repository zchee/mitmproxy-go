// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package omap provides an insertion-ordered map with string keys.
//
// The flow state codec needs Python dict semantics: keys keep the order in
// which they were first inserted, overwriting a key keeps its position, and
// deleting a key removes it from the order. Go maps iterate in random order,
// so serialising a state dictionary with them would not reproduce the key
// order mitmproxy writes into flow files.
//
// A key also records whether it is text or a byte string, the two key kinds
// a flow file can hold, so that a key read as Python bytes is written back
// as bytes. A key is identified by its bytes alone, whatever its kind.
package omap

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"iter"
	"maps"
	"reflect"
	"slices"
)

// indexThreshold is the entry count above which a Map maintains a hash index.
//
// Flow state dictionaries hold between three and twenty keys, and most hold
// fewer than ten. A linear scan over that many strings is faster than hashing
// and avoids allocating a Go map for every serialised object.
const indexThreshold = 8

type entry[V any] struct {
	key string
	val V
	// bytesKey marks a key that stands for a Python bytes object.
	bytesKey bool
}

// Map is a string-keyed map that remembers insertion order.
//
// The zero value is an empty map ready to use. A Map is not safe for
// concurrent use; callers that share one between goroutines must synchronise
// access themselves. Read-only methods accept a nil *Map and treat it as
// empty.
type Map[V any] struct {
	entries []entry[V]
	// index maps a key to its position in entries. It is nil while the map
	// holds at most indexThreshold entries.
	index map[string]int
}

// New returns an empty Map.
func New[V any]() *Map[V] {
	return &Map[V]{}
}

// NewWithCapacity returns an empty Map with room for n entries before it
// grows. State encoders know their key count up front and use it to build
// each dictionary with a single allocation.
func NewWithCapacity[V any](n int) *Map[V] {
	return &Map[V]{entries: make([]entry[V], 0, max(n, 0))}
}

// find returns the position of k in m.entries, or -1 when k is absent.
func (m *Map[V]) find(k string) int {
	if m.index != nil {
		if i, ok := m.index[k]; ok {
			return i
		}
		return -1
	}
	for i := range m.entries {
		if m.entries[i].key == k {
			return i
		}
	}
	return -1
}

func (m *Map[V]) buildIndex() {
	m.index = make(map[string]int, len(m.entries))
	for i, e := range m.entries {
		m.index[e.key] = i
	}
}

// Set associates v with k.
//
// A new key is appended at the end of the order, as a text key. Overwriting
// an existing key keeps its original position, as assignment to a Python
// dict does, and its kind.
func (m *Map[V]) Set(k string, v V) {
	if i := m.find(k); i >= 0 {
		m.entries[i].val = v
		return
	}
	m.add(entry[V]{key: k, val: v})
}

// SetBytesKey associates v with k and makes k a byte-string key, which need
// not be valid UTF-8. Like [Map.Set], it appends a new key and keeps an
// existing key in place.
func (m *Map[V]) SetBytesKey(k string, v V) {
	if i := m.find(k); i >= 0 {
		m.entries[i].val = v
		m.entries[i].bytesKey = true
		return
	}
	m.add(entry[V]{key: k, val: v, bytesKey: true})
}

// IsBytesKey reports whether k is present as a byte-string key.
func (m *Map[V]) IsBytesKey(k string) bool {
	if m == nil {
		return false
	}
	i := m.find(k)
	return i >= 0 && m.entries[i].bytesKey
}

// add appends an entry whose key is not present yet.
func (m *Map[V]) add(e entry[V]) {
	k := e.key
	m.entries = append(m.entries, e)
	switch {
	case m.index != nil:
		m.index[k] = len(m.entries) - 1
	case len(m.entries) > indexThreshold:
		m.buildIndex()
	}
}

// Get returns the value stored under k and whether k is present.
func (m *Map[V]) Get(k string) (V, bool) {
	if m == nil {
		var zero V
		return zero, false
	}
	if i := m.find(k); i >= 0 {
		return m.entries[i].val, true
	}
	var zero V
	return zero, false
}

// Has reports whether k is present.
func (m *Map[V]) Has(k string) bool {
	return m != nil && m.find(k) >= 0
}

// Pop removes k and returns the value it held and whether it was present.
//
// The state codec consumes a state dictionary key by key with Pop, so that
// the keys left over afterwards are exactly the unexpected ones.
func (m *Map[V]) Pop(k string) (V, bool) {
	var zero V
	if m == nil {
		return zero, false
	}
	i := m.find(k)
	if i < 0 {
		return zero, false
	}
	v := m.entries[i].val
	m.entries = slices.Delete(m.entries, i, i+1)
	if m.index != nil {
		delete(m.index, k)
		if len(m.entries) <= indexThreshold {
			m.index = nil
		} else {
			// Only the entries after the removed one moved.
			for j := i; j < len(m.entries); j++ {
				m.index[m.entries[j].key] = j
			}
		}
	}
	return v, true
}

// Delete removes k. Deleting an absent key is a no-op.
func (m *Map[V]) Delete(k string) {
	m.Pop(k)
}

// Len returns the number of entries.
func (m *Map[V]) Len() int {
	if m == nil {
		return 0
	}
	return len(m.entries)
}

// Keys returns the keys in insertion order. The returned slice is a copy.
func (m *Map[V]) Keys() []string {
	if m == nil || len(m.entries) == 0 {
		return nil
	}
	keys := make([]string, len(m.entries))
	for i, e := range m.entries {
		keys[i] = e.key
	}
	return keys
}

// All returns an iterator over the entries in insertion order.
//
// Overwriting the value of an existing key during iteration is allowed;
// adding or deleting keys during iteration has unspecified results.
func (m *Map[V]) All() iter.Seq2[string, V] {
	return func(yield func(string, V) bool) {
		if m == nil {
			return
		}
		for i := 0; i < len(m.entries); i++ {
			if !yield(m.entries[i].key, m.entries[i].val) {
				return
			}
		}
	}
}

// Clone returns a shallow copy of m: keys and order are copied, values are
// copied by assignment. Clone of a nil map returns nil.
func (m *Map[V]) Clone() *Map[V] {
	if m == nil {
		return nil
	}
	return &Map[V]{
		entries: slices.Clone(m.entries),
		index:   maps.Clone(m.index),
	}
}

// Equal reports whether m and o hold the same keys, of the same kinds, in
// the same order with equal values.
//
// Values are compared with [bytes.Equal] for []byte, element by element for
// []any, recursively for nested *Map values, and with [reflect.DeepEqual]
// otherwise. A nil map equals an empty one. Equal makes Map usable with
// github.com/google/go-cmp, which calls an Equal method when a type has one.
func (m *Map[V]) Equal(o *Map[V]) bool {
	if m.Len() != o.Len() {
		return false
	}
	if m.Len() == 0 {
		return true
	}
	for i := range m.entries {
		a, b := m.entries[i], o.entries[i]
		if a.key != b.key || a.bytesKey != b.bytesKey || !valueEqual(a.val, b.val) {
			return false
		}
	}
	return true
}

// equalAny lets valueEqual compare nested maps whose value type it does not
// know statically.
func (m *Map[V]) equalAny(other any) bool {
	o, ok := other.(*Map[V])
	return ok && m.Equal(o)
}

type anyEqualer interface {
	equalAny(other any) bool
}

func valueEqual(a, b any) bool {
	switch x := a.(type) {
	case anyEqualer:
		return x.equalAny(b)
	case []byte:
		y, ok := b.([]byte)
		return ok && bytes.Equal(x, y)
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !valueEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}

// String formats m like a Python dict literal, for debugging and test
// failure output. Byte-string keys carry a b prefix.
func (m *Map[V]) String() string {
	var b bytes.Buffer
	b.WriteByte('{')
	for i := range m.Len() {
		e := &m.entries[i]
		if b.Len() > 1 {
			b.WriteString(", ")
		}
		if e.bytesKey {
			b.WriteByte('b')
		}
		fmt.Fprintf(&b, "%q: %v", e.key, e.val)
	}
	b.WriteByte('}')
	return b.String()
}

// MarshalJSONTo encodes m as a JSON object whose members appear in insertion
// order. It implements [json.MarshalerTo].
func (m *Map[V]) MarshalJSONTo(enc *jsontext.Encoder) error {
	if m == nil {
		return enc.WriteToken(jsontext.Null)
	}
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	for _, e := range m.entries {
		if err := enc.WriteToken(jsontext.String(e.key)); err != nil {
			return err
		}
		if err := json.MarshalEncode(enc, e.val); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

// UnmarshalJSONFrom decodes a JSON object into m, appending members in the
// order they appear. It implements [json.UnmarshalerFrom].
//
// Like unmarshalling into a Go map with encoding/json/v2, existing entries
// are kept and members with the same name overwrite them in place. A JSON
// null clears m. When V is any, nested JSON objects decode as *Map[any] so
// that their member order is kept too.
func (m *Map[V]) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	switch kind := dec.PeekKind(); kind {
	case 'n':
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
		m.entries, m.index = nil, nil
		return nil
	case '{':
	case 0:
		_, err := dec.ReadToken()
		return err
	default:
		return fmt.Errorf("omap: cannot unmarshal JSON %v into an ordered map", kind)
	}
	if _, err := dec.ReadToken(); err != nil {
		return err
	}
	for dec.PeekKind() != '}' {
		tok, err := dec.ReadToken()
		if err != nil {
			return err
		}
		// A Token is only valid until the next call on dec, so copy the
		// name out before decoding the value.
		key := tok.String()
		var v V
		if err := decodeValue(dec, &v); err != nil {
			return err
		}
		m.Set(key, v)
	}
	_, err := dec.ReadToken()
	return err
}

func decodeValue[V any](dec *jsontext.Decoder, v *V) error {
	if pv, ok := any(v).(*any); ok {
		val, err := decodeAny(dec)
		if err != nil {
			return err
		}
		*pv = val
		return nil
	}
	return json.UnmarshalDecode(dec, v)
}

// decodeAny decodes the next JSON value like unmarshalling into an any does,
// except that objects become *Map[any] instead of map[string]any.
func decodeAny(dec *jsontext.Decoder) (any, error) {
	switch dec.PeekKind() {
	case '{':
		m := New[any]()
		if err := m.UnmarshalJSONFrom(dec); err != nil {
			return nil, err
		}
		return m, nil
	case '[':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		s := []any{}
		for dec.PeekKind() != ']' {
			v, err := decodeAny(dec)
			if err != nil {
				return nil, err
			}
			s = append(s, v)
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		return s, nil
	default:
		var v any
		if err := json.UnmarshalDecode(dec, &v); err != nil {
			return nil, err
		}
		return v, nil
	}
}
