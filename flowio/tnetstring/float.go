// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tnetstring

import (
	"bytes"
	"math"
	"strconv"
)

// appendFloat appends f formatted the way Python's repr(float) formats it.
//
// Python writes the shortest digit string that round-trips. It uses
// positional notation when the decimal exponent of the leading digit lies in
// [-4, 16), always with at least one fractional digit, and scientific notation
// otherwise, with an explicit exponent sign and at least two exponent digits.
// Infinities and NaN are written as inf, -inf and nan; Python drops the sign
// of a NaN.
func appendFloat(dst []byte, f float64) []byte {
	switch {
	case math.IsNaN(f):
		return append(dst, "nan"...)
	case math.IsInf(f, 1):
		return append(dst, "inf"...)
	case math.IsInf(f, -1):
		return append(dst, "-inf"...)
	}

	start := len(dst)
	dst = strconv.AppendFloat(dst, f, 'e', -1, 64)
	sci := dst[start:]
	// strconv ends the 'e' form with e±dd or e±ddd.
	e := bytes.LastIndexByte(sci, 'e')
	exp := 0
	for _, c := range sci[e+2:] {
		exp = exp*10 + int(c-'0')
	}
	if sci[e+1] == '-' {
		exp = -exp
	}
	if exp < -4 || exp >= 16 {
		// Go's 'e' format already matches Python here: shortest digits,
		// no trailing ".0", signed exponent of at least two digits.
		return dst
	}

	dst = strconv.AppendFloat(dst[:start], f, 'f', -1, 64)
	if bytes.IndexByte(dst[start:], '.') >= 0 {
		return dst
	}
	return append(dst, ".0"...)
}

// FormatFloat returns f formatted as Python's repr(float) formats it, which is
// how the tnetstring float payload is written.
func FormatFloat(f float64) string {
	return string(appendFloat(nil, f))
}
