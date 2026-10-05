// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package imagemeta

import (
	"fmt"
	"unicode/utf8"
)

// latin1 decodes b as ISO 8859-1, where every byte maps to the code point
// of the same value, so it never fails.
func latin1(b []byte) string {
	out := make([]rune, len(b))
	for i, c := range b {
		out[i] = rune(c)
	}
	return string(out)
}

// asciiText decodes b as ASCII. A byte outside the ASCII range is an
// error, as Python's strict "ascii" codec has it.
func asciiText(b []byte, what string) (string, error) {
	for _, c := range b {
		if c >= 0x80 {
			return "", fmt.Errorf("%s contains the non-ASCII byte %#x", what, c)
		}
	}
	return string(b), nil
}

// utf8Text decodes b as UTF-8. Invalid UTF-8 is an error, as Python's
// strict "utf-8" codec has it.
func utf8Text(b []byte, what string) (string, error) {
	if !utf8.Valid(b) {
		return "", fmt.Errorf("%s is not valid UTF-8", what)
	}
	return string(b), nil
}

// utf8BackslashReplace decodes b as UTF-8, writing every byte that is not
// part of a valid sequence as a \xNN escape, as Python's "backslashreplace"
// error handler does.
func utf8BackslashReplace(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	out := make([]byte, 0, len(b)+8)
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 {
			out = append(out, '\\', 'x', hexDigits[b[i]>>4], hexDigits[b[i]&0x0f])
		} else {
			out = append(out, b[i:i+size]...)
		}
		i += size
	}
	return string(out)
}

const hexDigits = "0123456789abcdef"
