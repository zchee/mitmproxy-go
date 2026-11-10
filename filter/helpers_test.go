// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package filter

import "io"

// Dump writes the expression tree the way upstream's dump method does: one
// line per node, indented by tabs, holding the upstream class name followed
// by the pattern for operators that have one.
func Dump(w io.Writer, e Expr) error {
	return dump(w, e, 0)
}

// Tokens returns every filter operator in upstream declaration order.
func Tokens() []Token {
	ts := make([]Token, 0, tokenEnd-1)
	for t := TokenAsset; t < tokenEnd; t++ {
		ts = append(ts, t)
	}
	return ts
}
