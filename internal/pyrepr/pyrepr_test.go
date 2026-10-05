// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package pyrepr

import (
	"math"
	"math/big"
	"strings"
	"testing"
	"unicode"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow/state"
)

// The expected values in this file were recorded with CPython 3.13.14
// (Unicode 15.1), the Python the differential tests run, by printing
// repr() of the same objects.

func TestStr(t *testing.T) {
	tests := map[string]struct {
		in   string
		want string
	}{
		"success: empty":                 {in: "", want: `''`},
		"success: plain":                 {in: "foo", want: `'foo'`},
		"success: single quote":          {in: "it's", want: `"it's"`},
		"success: double quote":          {in: `say "hi"`, want: `'say "hi"'`},
		"success: both quotes":           {in: `it's "x"`, want: `'it\'s "x"'`},
		"success: backslash":             {in: `a\b`, want: `'a\\b'`},
		"success: tab newline return":    {in: "a\tb\nc\rd", want: `'a\tb\nc\rd'`},
		"success: controls":              {in: "\x00\x01\x1f\x7f", want: `'\x00\x01\x1f\x7f'`},
		"success: c1 control":            {in: "\u0085", want: `'\x85'`},
		"success: nbsp and soft hyphen":  {in: "\u00a0\u00ad", want: `'\xa0\xad'`},
		"success: latin1 printable":      {in: "caf\u00e9", want: "'caf\u00e9'"},
		"success: zero width space":      {in: "a\u200bb", want: `'a\u200bb'`},
		"success: line separator":        {in: "\u2028", want: `'\u2028'`},
		"success: cjk":                   {in: "\u65e5\u672c\u8a9e", want: "'\u65e5\u672c\u8a9e'"},
		"success: emoji":                 {in: "\U0001F600", want: "'\U0001F600'"},
		"success: tag character":         {in: "\U000E0001", want: `'\U000e0001'`},
		"success: private use":           {in: "\ue000\U000F0000", want: `'\ue000\U000f0000'`},
		"success: replacement character": {in: "\ufffd", want: "'\ufffd'"},
		// A str cannot hold invalid UTF-8; these are the bytes decoded
		// with errors="surrogateescape".
		"success: invalid byte":       {in: "a\xffb", want: `'a\udcffb'`},
		"success: truncated sequence": {in: "\xe2\x82A", want: `'\udce2\udc82A'`},
		"success: encoded surrogate":  {in: "\xed\xa0\x80", want: `'\udced\udca0\udc80'`},
		"success: overlong":           {in: "\xc0\xaf", want: `'\udcc0\udcaf'`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Str(tt.in); got != tt.want {
				t.Errorf("Str(%q) = %s, want %s", tt.in, got, tt.want)
			}
			if got := string(AppendStr([]byte("x="), tt.in)); got != "x="+tt.want {
				t.Errorf("AppendStr(x=, %q) = %s, want x=%s", tt.in, got, tt.want)
			}
		})
	}
}

func TestBytes(t *testing.T) {
	tests := map[string]struct {
		in   []byte
		want string
	}{
		"success: nil":                {in: nil, want: `b''`},
		"success: empty":              {in: []byte{}, want: `b''`},
		"success: plain":              {in: []byte("foo"), want: `b'foo'`},
		"success: single quote":       {in: []byte("it's"), want: `b"it's"`},
		"success: double quote":       {in: []byte(`say "hi"`), want: `b'say "hi"'`},
		"success: both quotes":        {in: []byte(`it's "x"`), want: `b'it\'s "x"'`},
		"success: backslash":          {in: []byte(`a\b`), want: `b'a\\b'`},
		"success: tab newline return": {in: []byte("a\tb\nc\rd"), want: `b'a\tb\nc\rd'`},
		"success: controls":           {in: []byte("\x00\x01\x1f\x7f"), want: `b'\x00\x01\x1f\x7f'`},
		"success: high bytes":         {in: []byte("\x80\xa0\xff"), want: `b'\x80\xa0\xff'`},
		"success: utf8 text":          {in: []byte("caf\u00e9"), want: `b'caf\xc3\xa9'`},
		"success: invalid utf8":       {in: []byte("a\xffb\xc0"), want: `b'a\xffb\xc0'`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Bytes(tt.in); got != tt.want {
				t.Errorf("Bytes(%q) = %s, want %s", tt.in, got, tt.want)
			}
			if got := string(AppendBytes([]byte("x="), tt.in)); got != "x="+tt.want {
				t.Errorf("AppendBytes(x=, %q) = %s, want x=%s", tt.in, got, tt.want)
			}
		})
	}
}

func TestBytesPrefix(t *testing.T) {
	tests := map[string]struct {
		in   []byte
		n    int
		want string
	}{
		"success: quote chosen from the whole input": {in: []byte("'" + strings.Repeat("\x00", 20)), n: 10, want: `b"'\x00\x0`},
		"success: shorter than n":                    {in: []byte("ab"), n: 10, want: `b'ab'`},
		"success: cut inside an escape":              {in: []byte("\x00\x01\x02\x03"), n: 10, want: `b'\x00\x01`},
		"success: escaped quote":                     {in: []byte(`'"` + strings.Repeat("x", 20)), n: 10, want: `b'\'"xxxxx`},
		"success: exact fit":                         {in: []byte("ab"), n: 5, want: `b'ab'`},
		"success: zero":                              {in: []byte("ab"), n: 0, want: ``},
		"success: negative":                          {in: []byte("ab"), n: -1, want: ``},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := BytesPrefix(tt.in, tt.n); got != tt.want {
				t.Errorf("BytesPrefix(%q, %d) = %s, want %s", tt.in, tt.n, got, tt.want)
			}
			if full := Bytes(tt.in); tt.n >= 0 && !strings.HasPrefix(full, BytesPrefix(tt.in, tt.n)) {
				t.Errorf("BytesPrefix(%q, %d) is not a prefix of Bytes = %s", tt.in, tt.n, full)
			}
		})
	}
}

func TestValue(t *testing.T) {
	dict := state.NewMap(2)
	dict.SetBytesKey("raw", int64(1))
	dict.Set("k", []any{nil, true, false, 2.5, 1e16, int64(-3)})
	tests := map[string]struct {
		in   any
		want string
	}{
		"success: none":                {in: nil, want: "None"},
		"success: true":                {in: true, want: "True"},
		"success: false":               {in: false, want: "False"},
		"success: int64":               {in: int64(-3), want: "-3"},
		"success: int":                 {in: 42, want: "42"},
		"success: float":               {in: 2.0, want: "2.0"},
		"success: float exponent":      {in: 1e16, want: "1e+16"},
		"success: infinity":            {in: math.Inf(1), want: "inf"},
		"success: nan":                 {in: math.NaN(), want: "nan"},
		"success: str":                 {in: "it's", want: `"it's"`},
		"success: bytes":               {in: []byte("it's"), want: `b"it's"`},
		"success: list":                {in: []any{[]byte("it's"), "it's", state.NewMap(0), []any{}}, want: `[b"it's", "it's", {}, []]`},
		"success: dict with bytes key": {in: dict, want: `{b'raw': 1, 'k': [None, True, False, 2.5, 1e+16, -3]}`},
		"success: other value":         {in: big.NewInt(12345678901234567), want: "12345678901234567"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Value(tt.in); got != tt.want {
				t.Errorf("Value(%#v) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}

// TestUnicodeVersionSkew pins the one known way the helper departs from the
// pinned Python: Go's unicode tables are newer than Python 3.13's Unicode
// 15.1, so a character assigned since then is printable here and escaped by
// that Python ('\U0001fae9' for U+1FAE9, assigned in Unicode 16.0).
func TestUnicodeVersionSkew(t *testing.T) {
	const r = '\U0001FAE9'
	if !unicode.IsPrint(r) {
		t.Skipf("unicode %s does not know U+1FAE9; the skew is gone", unicode.Version)
	}
	if diff := gocmp.Diff("'"+string(r)+"'", Str(string(r))); diff != "" {
		t.Errorf("Str(U+1FAE9) (-want +got):\n%s", diff)
	}
}

func BenchmarkStr(b *testing.B) {
	inputs := map[string]string{
		"ascii":     strings.Repeat("GET /index.html HTTP/1.1 ", 8),
		"escapes":   strings.Repeat("it's \"x\"\t\\\n\x00", 8),
		"non-ascii": strings.Repeat("caf\u00e9 \u65e5\u672c \u200b\U0001F600 ", 8),
	}
	for name, s := range inputs {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(s)))
			for b.Loop() {
				_ = Str(s)
			}
		})
	}
}

func BenchmarkBytes(b *testing.B) {
	inputs := map[string][]byte{
		"ascii":  []byte(strings.Repeat("GET /index.html HTTP/1.1\r\n", 8)),
		"binary": []byte(strings.Repeat("\x00\x01\x7f\x80\xfe\xff'\"", 16)),
	}
	for name, p := range inputs {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(p)))
			for b.Loop() {
				_ = Bytes(p)
			}
		})
	}
}
