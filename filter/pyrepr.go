// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package filter

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
	"github.com/zchee/mitmproxy-go/internal/state"
)

// pyStr formats a state value the way Python's str() formats the object it
// stands for: a string as itself, everything else as repr(). ~meta matches
// against "key: str(value)" lines.
func pyStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	var b strings.Builder
	pyRepr(&b, v)
	return b.String()
}

// pyRepr writes Python's repr() of a state value. A list stands for both
// Python lists and tuples, which state values do not distinguish; it is
// written as a list.
func pyRepr(b *strings.Builder, v any) {
	switch v := v.(type) {
	case nil:
		b.WriteString("None")
	case bool:
		if v {
			b.WriteString("True")
		} else {
			b.WriteString("False")
		}
	case int64:
		b.WriteString(strconv.FormatInt(v, 10))
	case int:
		b.WriteString(strconv.Itoa(v))
	case float64:
		b.WriteString(tnetstring.FormatFloat(v))
	case string:
		reprStr(b, v)
	case []byte:
		reprBytes(b, v)
	case []any:
		b.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				b.WriteString(", ")
			}
			pyRepr(b, e)
		}
		b.WriteByte(']')
	case *state.Map:
		b.WriteByte('{')
		i := 0
		for k, e := range v.All() {
			if i > 0 {
				b.WriteString(", ")
			}
			reprStr(b, k)
			b.WriteString(": ")
			pyRepr(b, e)
			i++
		}
		b.WriteByte('}')
	default:
		fmt.Fprintf(b, "%v", v)
	}
}

// reprQuote picks the quote Python's repr uses: a single quote unless the
// text contains a single quote and no double quote.
func reprQuote(hasSingle, hasDouble bool) byte {
	if hasSingle && !hasDouble {
		return '"'
	}
	return '\''
}

func reprStr(b *strings.Builder, s string) {
	q := reprQuote(strings.Contains(s, "'"), strings.Contains(s, `"`))
	b.WriteByte(q)
	for _, r := range s {
		switch {
		case r == rune(q) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(b, `\x%02x`, r)
		case r < utf8.RuneSelf || unicode.IsPrint(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(b, `\u%04x`, r)
		default:
			fmt.Fprintf(b, `\U%08x`, r)
		}
	}
	b.WriteByte(q)
}

func reprBytes(b *strings.Builder, p []byte) {
	s := string(p)
	q := reprQuote(strings.Contains(s, "'"), strings.Contains(s, `"`))
	b.WriteByte('b')
	b.WriteByte(q)
	for _, c := range p {
		switch {
		case c == q || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '\t':
			b.WriteString(`\t`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c < 0x20 || c >= 0x7f:
			fmt.Fprintf(b, `\x%02x`, c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte(q)
}
