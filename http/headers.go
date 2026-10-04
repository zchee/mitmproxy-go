// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/zchee/mitmproxy-go/internal/state"
)

// Field is one raw header field: name and value exactly as they were
// received, including the original case of the name.
type Field struct {
	Name  []byte
	Value []byte
}

// Headers is an ordered list of raw header fields.
//
// Lookups are case-insensitive over ASCII; the stored fields keep their
// original spelling and order, so [Headers.Bytes] reproduces an HTTP/1
// header block byte for byte. The methods follow upstream's Headers type:
// [Headers.Get] folds repeated fields into one comma-separated value, and
// [Headers.Set] replaces values in place.
//
// A nil Headers is empty. Where a message attribute may be absent, such as
// trailers, nil means absent and a non-nil empty Headers means present.
type Headers []Field

// lowerASCII returns s with ASCII upper-case letters mapped to lower case,
// as Python's bytes.lower does. Other bytes are left alone.
func lowerASCII(s string) string {
	for i := range len(s) {
		if c := s[i]; 'A' <= c && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if c := b[j]; 'A' <= c && c <= 'Z' {
					b[j] = c + ('a' - 'A')
				}
			}
			return string(b)
		}
	}
	return s
}

// equalFoldASCII reports whether a and b are equal under ASCII case folding.
// Unlike bytes.EqualFold it does not fold non-ASCII runes, matching how
// upstream compares header names.
func equalFoldASCII(a []byte, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// GetAll returns every value of the named header, in order, without
// folding. Use it for Set-Cookie and Cookie, which must not be folded.
func (h Headers) GetAll(name string) []string {
	var out []string
	for _, f := range h {
		if equalFoldASCII(f.Name, name) {
			out = append(out, string(f.Value))
		}
	}
	return out
}

// Lookup returns the values of the named header joined with ", " and
// whether the header is present.
func (h Headers) Lookup(name string) (string, bool) {
	vals := h.GetAll(name)
	if len(vals) == 0 {
		return "", false
	}
	return strings.Join(vals, ", "), true
}

// Get returns the values of the named header joined with ", ", or the empty
// string when the header is absent.
func (h Headers) Get(name string) string {
	v, _ := h.Lookup(name)
	return v
}

// Has reports whether the named header is present.
func (h Headers) Has(name string) bool {
	return slices.ContainsFunc(h, func(f Field) bool { return equalFoldASCII(f.Name, name) })
}

// Set sets the named header to a single value. See [Headers.SetAll].
func (h *Headers) Set(name, value string) {
	h.SetAll(name, []string{value})
}

// SetAll replaces the values of the named header.
//
// Existing occurrences receive the new values in order and keep their
// position and name spelling; surplus occurrences are removed; values left
// over are appended under name as given.
func (h *Headers) SetAll(name string, values []string) {
	out := make(Headers, 0, len(*h)+len(values))
	for _, f := range *h {
		if !equalFoldASCII(f.Name, name) {
			out = append(out, f)
			continue
		}
		if len(values) > 0 {
			out = append(out, Field{Name: f.Name, Value: []byte(values[0])})
			values = values[1:]
		}
	}
	for _, v := range values {
		out = append(out, Field{Name: []byte(name), Value: []byte(v)})
	}
	*h = out
}

// Add appends a field, keeping any existing ones with the same name.
func (h *Headers) Add(name, value string) {
	*h = append(*h, Field{Name: []byte(name), Value: []byte(value)})
}

// Insert inserts a field at position i of the raw field list. It panics if
// i is out of range, like [slices.Insert].
func (h *Headers) Insert(i int, name, value string) {
	*h = slices.Insert(*h, i, Field{Name: []byte(name), Value: []byte(value)})
}

// Del removes every occurrence of the named header and reports whether any
// was present.
func (h *Headers) Del(name string) bool {
	n := len(*h)
	*h = slices.DeleteFunc(*h, func(f Field) bool { return equalFoldASCII(f.Name, name) })
	return len(*h) != n
}

// Keys returns each distinct header name once, in the spelling of its first
// occurrence.
func (h Headers) Keys() []string {
	var keys []string
	seen := make(map[string]bool, len(h))
	for _, f := range h {
		k := lowerASCII(string(f.Name))
		if !seen[k] {
			seen[k] = true
			keys = append(keys, string(f.Name))
		}
	}
	return keys
}

// Bytes returns the fields as an HTTP/1 header block: one "name: value\r\n"
// line per field, in order, with the original name case. Empty headers give
// an empty slice.
func (h Headers) Bytes() []byte {
	var b bytes.Buffer
	for _, f := range h {
		b.Write(f.Name)
		b.WriteString(": ")
		b.Write(f.Value)
		b.WriteString("\r\n")
	}
	return b.Bytes()
}

// Clone returns a deep copy of h. Clone(nil) is nil.
func (h Headers) Clone() Headers {
	if h == nil {
		return nil
	}
	out := make(Headers, len(h))
	for i, f := range h {
		out[i] = Field{Name: slices.Clone(f.Name), Value: slices.Clone(f.Value)}
	}
	return out
}

// state returns the headers as upstream serialises them: a list of
// (name, value) byte pairs.
func (h Headers) state() []any {
	out := make([]any, len(h))
	for i, f := range h {
		out[i] = []any{state.Bytes(f.Name), state.Bytes(f.Value)}
	}
	return out
}

func optHeadersState(h Headers) any {
	if h == nil {
		return nil
	}
	return h.state()
}

// headersFromState parses a list of (name, value) byte pairs. The result is
// non-nil even when the list is empty.
func headersFromState(v any) (Headers, error) {
	l, err := state.AsList(v)
	if err != nil {
		return nil, err
	}
	out := make(Headers, len(l))
	for i, e := range l {
		pair, err := state.Tuple(e, 2)
		if err != nil {
			return nil, fmt.Errorf("header %d: %w", i, err)
		}
		name, err := state.AsBytes(pair[0])
		if err != nil {
			return nil, fmt.Errorf("header %d name: %w", i, err)
		}
		value, err := state.AsBytes(pair[1])
		if err != nil {
			return nil, fmt.Errorf("header %d value: %w", i, err)
		}
		out[i] = Field{Name: name, Value: value}
	}
	return out, nil
}
