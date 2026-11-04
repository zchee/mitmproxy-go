// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package encoding

import "slices"

// Decode exercises the unbounded core for round-trip and limit comparisons.
func Decode(data []byte, encoding string) ([]byte, error) {
	return decode(data, encoding, unlimited)
}

// Encodings supplies an owned vocabulary to codec tests and benchmarks.
func Encodings() []string { return slices.Clone(encodings) }
