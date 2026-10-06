// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

import (
	"fmt"
	"iter"
	"math"
	"slices"
)

// Fragmentizer retains an original plaintext fragment layout for equal-length
// content, or divides changed content into pieces of at most 4000 bytes.
// The zero value treats content as an injected message without original frames.
// It is safe for concurrent use after construction.
type Fragmentizer struct {
	lengths []int
	total   int
}

// NewFragmentizer copies the original plaintext fragment lengths, including
// empty fragments. Negative lengths and a sum overflowing int are rejected.
// A compressed message decoded only at FIN has one whole-message length here.
func NewFragmentizer(lengths []int) (Fragmentizer, error) {
	total := 0
	for _, n := range lengths {
		if n < 0 || n > math.MaxInt-total {
			return Fragmentizer{}, fmt.Errorf("websocket: invalid fragment length %d", n)
		}
		total += n
	}
	return Fragmentizer{lengths: slices.Clone(lengths), total: total}, nil
}

// Fragments yields borrowed payload slices and their FIN flags. Equal-length
// content reuses every original size; other content uses 4000-byte pieces.
// Empty content always yields a final frame, including without original sizes.
// The caller must not mutate content while iterating.
func (f Fragmentizer) Fragments(content []byte) iter.Seq2[[]byte, bool] {
	return func(yield func([]byte, bool) bool) {
		if len(f.lengths) > 0 && len(content) == f.total {
			offset := 0
			for i, n := range f.lengths {
				if !yield(content[offset:offset+n], i == len(f.lengths)-1) {
					return
				}
				offset += n
			}
			return
		}
		for len(content) > 4000 {
			if !yield(content[:4000], false) {
				return
			}
			content = content[4000:]
		}
		yield(content, true)
	}
}
