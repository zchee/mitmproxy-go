// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tnetstring

import (
	"bytes"
	"iter"
	"math/big"
)

// dictIndexThreshold is the entry count above which a Dict keeps a hash index.
//
// Flow state dictionaries hold a handful of keys, where a linear scan beats
// hashing and avoids allocating a Go map per decoded object. Large
// dictionaries, which only adversarial input produces, still decode in linear
// time.
const dictIndexThreshold = 8

type dictEntry struct {
	key   string
	value any
}

// Dict is a tnetstring dictionary: string keys in insertion order.
//
// It follows Python dict semantics. Setting an existing key replaces its value
// and keeps its position, and Equal ignores order, as Python's == does.
//
// The zero value is an empty Dict ready to use. A Dict is not safe for
// concurrent use. Read-only methods accept a nil *Dict and treat it as empty.
type Dict struct {
	entries []dictEntry
	index   map[string]int
}

// NewDict returns an empty Dict with room for n entries.
func NewDict(n int) *Dict {
	return &Dict{entries: make([]dictEntry, 0, n)}
}

func (d *Dict) find(key string) int {
	if d == nil {
		return -1
	}
	if d.index != nil {
		if i, ok := d.index[key]; ok {
			return i
		}
		return -1
	}
	for i := range d.entries {
		if d.entries[i].key == key {
			return i
		}
	}
	return -1
}

// Set stores value under key. A new key is appended; an existing key keeps its
// position.
func (d *Dict) Set(key string, value any) {
	if i := d.find(key); i >= 0 {
		d.entries[i].value = value
		return
	}
	d.entries = append(d.entries, dictEntry{key: key, value: value})
	switch {
	case d.index != nil:
		d.index[key] = len(d.entries) - 1
	case len(d.entries) > dictIndexThreshold:
		d.index = make(map[string]int, len(d.entries)*2)
		for i := range d.entries {
			d.index[d.entries[i].key] = i
		}
	}
}

// Get returns the value stored under key and whether the key is present.
func (d *Dict) Get(key string) (any, bool) {
	if i := d.find(key); i >= 0 {
		return d.entries[i].value, true
	}
	return nil, false
}

// Len returns the number of entries.
func (d *Dict) Len() int {
	if d == nil {
		return 0
	}
	return len(d.entries)
}

// Keys returns the keys in insertion order.
func (d *Dict) Keys() []string {
	if d == nil {
		return nil
	}
	keys := make([]string, len(d.entries))
	for i := range d.entries {
		keys[i] = d.entries[i].key
	}
	return keys
}

// All iterates over the entries in insertion order.
func (d *Dict) All() iter.Seq2[string, any] {
	return func(yield func(string, any) bool) {
		if d == nil {
			return
		}
		for i := range d.entries {
			if !yield(d.entries[i].key, d.entries[i].value) {
				return
			}
		}
	}
}

// Equal reports whether d and o hold the same keys with equal values,
// regardless of order.
//
// Values are compared as Python compares the decoded objects: lists element
// by element, integers by numeric value whether held as int64 or *big.Int, and
// floats with IEEE semantics, so a NaN is never equal to anything.
func (d *Dict) Equal(o *Dict) bool {
	if d.Len() != o.Len() {
		return false
	}
	for k, v := range d.All() {
		ov, ok := o.Get(k)
		if !ok || !Equal(v, ov) {
			return false
		}
	}
	return true
}

// Equal reports whether two tnetstring values are equal under the rules
// described on [Dict.Equal].
func Equal(a, b any) bool {
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
			if !Equal(a[i], b[i]) {
				return false
			}
		}
		return true
	case *Dict:
		b, ok := b.(*Dict)
		return ok && a.Equal(b)
	}
	return false
}
