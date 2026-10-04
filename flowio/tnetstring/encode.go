// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tnetstring

import (
	"fmt"
	"io"
	"math/big"
	"slices"
	"strconv"
	"unicode/utf8"
)

// Dumps returns the tnetstring encoding of v.
//
// See the package documentation for the accepted types. Strings must be valid
// UTF-8, as Python's str.encode("utf8") requires. A nil *Dict is written as an
// empty dictionary and a nil []byte as an empty byte string.
func Dumps(v any) ([]byte, error) {
	var e encoder
	if err := e.value(v, 0); err != nil {
		return nil, err
	}
	return e.buf[e.off:], nil
}

// Dump writes the tnetstring encoding of v to w.
func Dump(w io.Writer, v any) error {
	b, err := Dumps(v)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// encoder builds the output from the end towards the start, as mitmproxy's
// _rdumpq does: a container's length prefix is known only after its payload
// has been written. The output occupies buf[off:].
type encoder struct {
	buf []byte
	off int
}

func (e *encoder) size() int { return len(e.buf) - e.off }

// reserve makes room for n more bytes in front of the output.
func (e *encoder) reserve(n int) {
	if e.off >= n {
		return
	}
	used := e.size()
	c := max(2*len(e.buf), used+n, 256)
	nb := make([]byte, c)
	copy(nb[c-used:], e.buf[e.off:])
	e.buf, e.off = nb, c-used
}

func (e *encoder) prependByte(c byte) {
	e.reserve(1)
	e.off--
	e.buf[e.off] = c
}

func (e *encoder) prepend(p []byte) {
	e.reserve(len(p))
	e.off -= len(p)
	copy(e.buf[e.off:], p)
}

func (e *encoder) prependString(s string) {
	e.reserve(len(s))
	e.off -= len(s)
	copy(e.buf[e.off:], s)
}

// prefix writes the "N:" length prefix for a payload of n bytes.
func (e *encoder) prefix(n int) {
	var tmp [20]byte
	e.prependByte(':')
	e.prepend(strconv.AppendInt(tmp[:0], int64(n), 10))
}

// scalar writes a complete element whose payload is already formatted.
func (e *encoder) scalar(payload []byte, tag byte) {
	e.prependByte(tag)
	e.prepend(payload)
	e.prefix(len(payload))
}

func (e *encoder) text(s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("tnetstring: string is not valid UTF-8: %s", quote([]byte(s)))
	}
	e.prependByte(';')
	e.prependString(s)
	e.prefix(len(s))
	return nil
}

func (e *encoder) value(v any, depth int) error {
	var tmp [32]byte
	switch v := v.(type) {
	case nil:
		e.prependString("0:~")
	case bool:
		if v {
			e.prependString("4:true!")
		} else {
			e.prependString("5:false!")
		}
	case int64:
		e.scalar(strconv.AppendInt(tmp[:0], v, 10), '#')
	case int:
		e.scalar(strconv.AppendInt(tmp[:0], int64(v), 10), '#')
	case int32:
		e.scalar(strconv.AppendInt(tmp[:0], int64(v), 10), '#')
	case int16:
		e.scalar(strconv.AppendInt(tmp[:0], int64(v), 10), '#')
	case int8:
		e.scalar(strconv.AppendInt(tmp[:0], int64(v), 10), '#')
	case uint64:
		e.scalar(strconv.AppendUint(tmp[:0], v, 10), '#')
	case uint:
		e.scalar(strconv.AppendUint(tmp[:0], uint64(v), 10), '#')
	case uint32:
		e.scalar(strconv.AppendUint(tmp[:0], uint64(v), 10), '#')
	case uint16:
		e.scalar(strconv.AppendUint(tmp[:0], uint64(v), 10), '#')
	case uint8:
		e.scalar(strconv.AppendUint(tmp[:0], uint64(v), 10), '#')
	case *big.Int:
		if v == nil {
			return fmt.Errorf("%w: nil *big.Int", ErrUnsupportedType)
		}
		digits := v.Append(nil, 10)
		n := len(digits)
		if v.Sign() < 0 {
			n-- // Python does not count the sign.
		}
		if n > maxIntDigits {
			return fmt.Errorf("tnetstring: integer has %d digits, more than the limit of %d", n, maxIntDigits)
		}
		e.scalar(digits, '#')
	case float64:
		e.scalar(appendFloat(tmp[:0], v), '^')
	case float32:
		e.scalar(appendFloat(tmp[:0], float64(v)), '^')
	case []byte:
		e.scalar(v, ',')
	case string:
		return e.text(v)
	case []any:
		if depth >= maxDepth {
			return fmt.Errorf("tnetstring: value nests deeper than %d levels", maxDepth)
		}
		e.prependByte(']')
		start := e.size()
		for _, item := range slices.Backward(v) {
			if err := e.value(item, depth+1); err != nil {
				return err
			}
		}
		e.prefix(e.size() - start)
	case *Dict:
		if depth >= maxDepth {
			return fmt.Errorf("tnetstring: value nests deeper than %d levels", maxDepth)
		}
		e.prependByte('}')
		start := e.size()
		// Walking forwards while prepending leaves the entries in reverse
		// insertion order, as mitmproxy writes them.
		for k, val := range v.All() {
			if err := e.value(val, depth+1); err != nil {
				return err
			}
			if err := e.text(k); err != nil {
				return err
			}
		}
		e.prefix(e.size() - start)
	default:
		return fmt.Errorf("%w: %v (%T)", ErrUnsupportedType, v, v)
	}
	return nil
}
