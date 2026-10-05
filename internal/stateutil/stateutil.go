// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package stateutil holds the helpers the flow models share when they write
// their serialised state and when they stamp a new flow or connection.
//
// The read side, and the vocabulary of the state tree itself, is the public
// package github.com/zchee/mitmproxy-go/flow/state. These helpers only shape
// Go values into state values (None for a nil pointer, an empty byte string
// for a nil slice) and produce upstream's timestamp and identifier formats,
// so they stay internal and no exported signature uses them.
package stateutil

import (
	"crypto/rand"
	"time"
)

// Opt returns *p, or nil when p is nil. It turns an optional Go field into
// the state value for a Python attribute that may be None.
func Opt[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
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
// that are never None. It is the write-side counterpart of the state
// package's Decoder.Bytes, which reads such an attribute back.
func Bytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// BytesList converts a list of byte strings to a state list. Every element,
// and the list itself, is non-nil.
func BytesList(bs [][]byte) []any {
	out := make([]any, len(bs))
	for i, b := range bs {
		out[i] = Bytes(b)
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
