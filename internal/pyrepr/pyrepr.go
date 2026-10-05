// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package pyrepr renders values the way Python's repr() renders the objects
// they stand for, which is how mitmproxy shows values inside its messages
// and filter matches.
//
// The rules are CPython's (Objects/unicodeobject.c unicode_repr and
// Objects/bytesobject.c PyBytes_Repr). Whether a non-ASCII character is
// printable comes from Go's unicode tables, so a code point assigned in a
// Unicode version newer than the running Python's is written as itself here
// and escaped by that Python.
package pyrepr

import (
	"bytes"
	"fmt"
	"iter"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
)

// Map is an ordered dictionary whose keys are text or byte strings, such as
// *omap.Map[any].
type Map interface {
	// All yields the entries in order.
	All() iter.Seq2[string, any]
	// IsBytesKey reports whether key k stands for a Python bytes object.
	IsBytesKey(k string) bool
}

// Str returns the repr of the Python str s.
//
// A byte of s that is not part of valid UTF-8 is written as the lone
// surrogate Python's "surrogateescape" error handler decodes it to, \udcXX,
// which is how mitmproxy turns arbitrary bytes into text (header values,
// command-line arguments).
func Str(s string) string {
	return string(AppendStr(make([]byte, 0, len(s)+2), s))
}

// AppendStr appends the repr of the Python str s to dst, as Str does, and
// returns the extended buffer.
func AppendStr(dst []byte, s string) []byte {
	q := quote(strings.IndexByte(s, '\'') >= 0, strings.IndexByte(s, '"') >= 0)
	dst = append(dst, q)
	for i := 0; i < len(s); {
		if n := plainRun(s[i:], q); n > 0 {
			dst = append(dst, s[i:i+n]...)
			i += n
			continue
		}
		c := s[i]
		if c < utf8.RuneSelf {
			dst = appendASCII(dst, c, q)
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			// surrogateescape maps an undecodable byte to U+DC00 plus
			// the byte; only bytes from 0x80 up are ever undecodable.
			dst = appendHex(append(dst, `\udc`...), c)
		case unicode.IsPrint(r):
			dst = append(dst, s[i:i+size]...)
		case r <= 0xff:
			dst = appendHex(append(dst, `\x`...), byte(r))
		case r <= 0xffff:
			dst = appendHex(appendHex(append(dst, `\u`...), byte(r>>8)), byte(r))
		default:
			dst = append(dst, `\U00`...)
			dst = appendHex(appendHex(appendHex(dst, byte(r>>16)), byte(r>>8)), byte(r))
		}
		i += size
	}
	return append(dst, q)
}

// Bytes returns the repr of the Python bytes object p.
func Bytes(p []byte) string {
	return string(AppendBytes(make([]byte, 0, len(p)+3), p))
}

// AppendBytes appends the repr of the Python bytes object p to dst and
// returns the extended buffer.
func AppendBytes(dst, p []byte) []byte {
	q := quote(bytes.IndexByte(p, '\'') >= 0, bytes.IndexByte(p, '"') >= 0)
	dst = append(dst, 'b', q)
	for i := 0; i < len(p); {
		if n := plainRun(p[i:], q); n > 0 {
			dst = append(dst, p[i:i+n]...)
			i += n
			continue
		}
		dst = appendByte(dst, p[i], q)
		i++
	}
	return append(dst, q)
}

// BytesPrefix returns the first n characters of the repr of the Python bytes
// object p, as Python's repr(p)[:n]. Only as much of p is escaped as the
// prefix needs, though the quote is chosen from all of p.
func BytesPrefix(p []byte, n int) string {
	n = max(n, 0)
	q := quote(bytes.IndexByte(p, '\'') >= 0, bytes.IndexByte(p, '"') >= 0)
	dst := make([]byte, 0, n+4)
	dst = append(dst, 'b', q)
	for _, c := range p {
		if len(dst) >= n {
			break
		}
		dst = appendByte(dst, c, q)
	}
	dst = append(dst, q)
	return string(dst[:min(len(dst), n)])
}

// Value returns the repr of the Python object v stands for: nil is None, a
// bool, an int or int64, a float64, a string (str), a []byte (bytes), a
// []any (a list; Python tuples are written as lists too) or a Map (a dict).
// Any other value is written in Go's %v format.
func Value(v any) string {
	return string(AppendValue(make([]byte, 0, 64), v))
}

// AppendValue appends the repr of v to dst, as Value does, and returns the
// extended buffer.
func AppendValue(dst []byte, v any) []byte {
	switch x := v.(type) {
	case nil:
		return append(dst, "None"...)
	case bool:
		if x {
			return append(dst, "True"...)
		}
		return append(dst, "False"...)
	case int64:
		return strconv.AppendInt(dst, x, 10)
	case int:
		return strconv.AppendInt(dst, int64(x), 10)
	case float64:
		return append(dst, tnetstring.FormatFloat(x)...)
	case string:
		return AppendStr(dst, x)
	case []byte:
		return AppendBytes(dst, x)
	case []any:
		dst = append(dst, '[')
		for i, e := range x {
			if i > 0 {
				dst = append(dst, ", "...)
			}
			dst = AppendValue(dst, e)
		}
		return append(dst, ']')
	case Map:
		return appendMap(dst, x)
	default:
		return fmt.Appendf(dst, "%v", v)
	}
}

// appendMap appends the repr of the dict m. It is apart from AppendValue
// because the range-over-func loop captures dst, which would move dst to the
// heap on every AppendValue call.
func appendMap(dst []byte, m Map) []byte {
	dst = append(dst, '{')
	i := 0
	for k, e := range m.All() {
		if i > 0 {
			dst = append(dst, ", "...)
		}
		if m.IsBytesKey(k) {
			dst = AppendBytes(dst, []byte(k))
		} else {
			dst = AppendStr(dst, k)
		}
		dst = append(dst, ": "...)
		dst = AppendValue(dst, e)
		i++
	}
	return append(dst, '}')
}

// quote picks the quote character Python's repr uses: a single quote, unless
// the text contains a single quote and no double quote.
func quote(hasSingle, hasDouble bool) byte {
	if hasSingle && !hasDouble {
		return '"'
	}
	return '\''
}

// plainRun returns the length of the leading run of s that a repr quoted
// with q writes unchanged: printable ASCII other than q and the backslash.
func plainRun[S ~string | ~[]byte](s S, q byte) int {
	for i := range len(s) {
		if c := s[i]; c < 0x20 || c >= 0x7f || c == q || c == '\\' {
			return i
		}
	}
	return len(s)
}

// appendASCII appends the repr of the ASCII character c inside a str quoted
// with q.
func appendASCII(dst []byte, c, q byte) []byte {
	switch {
	case c == q || c == '\\':
		return append(dst, '\\', c)
	case c == '\t':
		return append(dst, `\t`...)
	case c == '\n':
		return append(dst, `\n`...)
	case c == '\r':
		return append(dst, `\r`...)
	case c < 0x20 || c == 0x7f:
		return appendHex(append(dst, `\x`...), c)
	default:
		return append(dst, c)
	}
}

// appendByte appends the repr of the byte c inside a bytes object quoted
// with q.
func appendByte(dst []byte, c, q byte) []byte {
	if c >= 0x80 {
		return appendHex(append(dst, `\x`...), c)
	}
	return appendASCII(dst, c, q)
}

const hexDigits = "0123456789abcdef"

// appendHex appends c as two lower-case hexadecimal digits.
func appendHex(dst []byte, c byte) []byte {
	return append(dst, hexDigits[c>>4], hexDigits[c&0x0f])
}
