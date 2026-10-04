// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowio

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
	"github.com/zchee/mitmproxy-go/internal/state"
)

// VersionError reports a flow whose format version cannot be read.
type VersionError struct {
	// Version is the flow's version as mitmproxy renders it: an integer
	// such as 17, or a tuple such as (0, 10) for files written before
	// mitmproxy 4.
	Version string
	// Newer reports that the file comes from a newer mitmproxy.
	Newer bool
}

// Error returns mitmproxy's message for an unreadable version, with
// mitmproxy-go's name and version in place of mitmproxy's.
func (e *VersionError) Error() string {
	if e.Newer {
		return fmt.Sprintf("%s cannot read files with flow format version %s, please update mitmproxy.", versionName, e.Version)
	}
	return fmt.Sprintf("%s cannot read files with flow format version %s.", versionName, e.Version)
}

// converters holds the migrations from each readable older version to the
// next one.
var converters = map[int64]func(*state.Map) error{}

// migrate brings a flow's state to [flow.FormatVersion], as mitmproxy's
// compat.migrate_flow does, but only from the versions in converters.
func migrate(data *state.Map) error {
	for {
		v, _ := data.Get("version")
		n, isInt := v.(int64)
		if !isInt {
			s, err := renderTupleVersion(v)
			if err != nil {
				return err
			}
			return &VersionError{Version: s}
		}
		if n == flow.FormatVersion {
			return nil
		}
		convert, ok := converters[n]
		if !ok {
			return &VersionError{Version: strconv.FormatInt(n, 10), Newer: n > flow.FormatVersion}
		}
		if err := convert(data); err != nil {
			return err
		}
	}
}

// renderTupleVersion renders a version that is not an integer the way
// mitmproxy does: tuple(version)[:2]. Files written before mitmproxy 4
// store the mitmproxy release as a list, such as [0, 10, 1].
func renderTupleVersion(v any) (string, error) {
	var items []any
	switch x := v.(type) {
	case bool:
		// A Python bool is an int; no version is ever True or False.
		if x {
			return "True", nil
		}
		return "False", nil
	case []any:
		items = x
	case string:
		for _, r := range x {
			items = append(items, string(r))
		}
	case []byte:
		for _, c := range x {
			items = append(items, int64(c))
		}
	case *state.Map:
		for _, k := range x.Keys() {
			items = append(items, k)
		}
	case nil:
		return "", fmt.Errorf("invalid flow: the version is missing or None")
	default:
		return "", fmt.Errorf("invalid flow: the version is a %s, not an integer or a tuple", state.TypeName(v))
	}
	items = items[:min(len(items), 2)]
	var b strings.Builder
	b.WriteByte('(')
	for i, it := range items {
		if i > 0 {
			b.WriteString(", ")
		}
		writeRepr(&b, it)
	}
	if len(items) == 1 {
		b.WriteByte(',')
	}
	b.WriteByte(')')
	return b.String(), nil
}

// writeRepr writes v as Python's repr writes the equivalent object.
func writeRepr(b *strings.Builder, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("None")
	case bool:
		if x {
			b.WriteString("True")
		} else {
			b.WriteString("False")
		}
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case float64:
		b.WriteString(tnetstring.FormatFloat(x))
	case string:
		writeStrRepr(b, x)
	case []byte:
		writeBytesRepr(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			writeRepr(b, e)
		}
		b.WriteByte(']')
	case *state.Map:
		b.WriteByte('{')
		i := 0
		for k, e := range x.All() {
			if i > 0 {
				b.WriteString(", ")
			}
			i++
			writeStrRepr(b, k)
			b.WriteString(": ")
			writeRepr(b, e)
		}
		b.WriteByte('}')
	default:
		fmt.Fprintf(b, "%v", v)
	}
}

// reprQuote picks the quote Python's repr uses: a single quote, unless the
// text contains one and no double quote.
func reprQuote(hasSingle, hasDouble bool) byte {
	if hasSingle && !hasDouble {
		return '"'
	}
	return '\''
}

func writeStrRepr(b *strings.Builder, s string) {
	q := reprQuote(strings.ContainsRune(s, '\''), strings.ContainsRune(s, '"'))
	b.WriteByte(q)
	for _, r := range s {
		switch {
		case r == '\\' || r == rune(q):
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			fmt.Fprintf(b, `\x%02x`, r)
		case r == utf8.RuneError || !unicode.IsPrint(r):
			if r <= 0xffff {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				fmt.Fprintf(b, `\U%08x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(q)
}

func writeBytesRepr(b *strings.Builder, p []byte) {
	q := reprQuote(strings.IndexByte(string(p), '\'') >= 0, strings.IndexByte(string(p), '"') >= 0)
	b.WriteByte('b')
	b.WriteByte(q)
	for _, c := range p {
		switch {
		case c == '\\' || c == q:
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
