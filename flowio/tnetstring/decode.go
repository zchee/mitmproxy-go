// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tnetstring

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"unicode/utf8"
)

// Loads decodes b, which must hold exactly one tnetstring value.
//
// Unlike mitmproxy's loads, which ignores anything after the first value,
// trailing bytes are an error.
func Loads(b []byte) (any, error) {
	v, rest, err := Pop(b)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, syntaxErrorf("not a tnetstring: %d bytes of trailing data: %s", len(rest), quote(rest))
	}
	return v, nil
}

// Pop decodes the first tnetstring value in b and returns it with the bytes
// that follow it. The returned value does not alias b.
func Pop(b []byte) (value any, rest []byte, err error) {
	return pop(b, 0)
}

// maxLoadPrefix is the longest length prefix Load accepts, as in mitmproxy.
const maxLoadPrefix = 12

// Load reads exactly one tnetstring value from r and decodes it.
//
// Load reads no byte past the end of the value. It reads one byte at a time
// while parsing the length prefix, so r should be buffered; a reader that
// implements [io.ByteReader], such as a [bufio.Reader], is used as one. Load
// returns io.EOF, unwrapped, when r is exhausted before the first byte, and
// an error wrapping io.ErrUnexpectedEOF when a value is cut short.
func Load(r io.Reader) (any, error) {
	br, ok := r.(io.ByteReader)
	if !ok {
		br = &singleByteReader{r: r}
	}
	c, err := br.ReadByte()
	if err != nil {
		return nil, err
	}
	var n int64
	digits := 0
	for '0' <= c && c <= '9' {
		digits++
		if digits > maxLoadPrefix {
			return nil, syntaxErrorf("not a tnetstring: absurdly large length prefix")
		}
		n = n*10 + int64(c-'0')
		if c, err = br.ReadByte(); err != nil {
			return nil, truncated(err)
		}
	}
	if digits == 0 || c != ':' {
		return nil, syntaxErrorf("not a tnetstring: missing or invalid length prefix")
	}

	payload, err := readN(r, n)
	if err != nil {
		return nil, truncated(err)
	}
	tag, err := br.ReadByte()
	if err != nil {
		return nil, truncated(err)
	}
	return parse(tag, payload, 0)
}

// singleByteReader adapts an io.Reader to io.ByteReader without reading ahead.
type singleByteReader struct {
	r   io.Reader
	buf [1]byte
}

func (s *singleByteReader) ReadByte() (byte, error) {
	if _, err := io.ReadFull(s.r, s.buf[:]); err != nil {
		return 0, err
	}
	return s.buf[0], nil
}

// readN reads exactly n bytes from r. Memory grows with the bytes actually
// read, so a forged length prefix cannot force a large allocation.
func readN(r io.Reader, n int64) ([]byte, error) {
	const direct = 1 << 20
	if n <= direct {
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		return b, err
	}
	b, err := io.ReadAll(io.LimitReader(r, n))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) < n {
		return nil, io.ErrUnexpectedEOF
	}
	return b, nil
}

func truncated(err error) error {
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return fmt.Errorf("not a tnetstring: truncated value: %w", err)
}

func pop(b []byte, depth int) (any, []byte, error) {
	// The length prefix: one or more ASCII digits, then ':'.
	n, i := 0, 0
	for ; i < len(b) && '0' <= b[i] && b[i] <= '9'; i++ {
		n = n*10 + int(b[i]-'0')
		if n > len(b) {
			return nil, nil, syntaxErrorf("not a tnetstring: invalid length prefix: %s", quote(b[:i+1]))
		}
	}
	if i == 0 || i == len(b) || b[i] != ':' {
		return nil, nil, syntaxErrorf("not a tnetstring: missing or invalid length prefix: %s", quote(b))
	}
	b = b[i+1:]
	if n >= len(b) {
		return nil, nil, syntaxErrorf("not a tnetstring: invalid length prefix: %d", n)
	}
	v, err := parse(b[n], b[:n], depth)
	if err != nil {
		return nil, nil, err
	}
	return v, b[n+1:], nil
}

func parse(tag byte, data []byte, depth int) (any, error) {
	switch tag {
	case ',':
		return bytes.Clone(data), nil
	case ';':
		if !utf8.Valid(data) {
			return nil, syntaxErrorf("not a tnetstring: invalid UTF-8 in string: %s", quote(data))
		}
		return string(data), nil
	case '#':
		return parseInt(data)
	case '^':
		return parseFloat(data)
	case '!':
		switch string(data) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
		return nil, syntaxErrorf("not a tnetstring: invalid boolean literal: %s", quote(data))
	case '~':
		if len(data) > 0 {
			return nil, syntaxErrorf("not a tnetstring: invalid null literal: %s", quote(data))
		}
		return nil, nil
	case ']':
		if depth >= maxDepth {
			return nil, syntaxErrorf("not a tnetstring: nesting deeper than %d levels", maxDepth)
		}
		list := []any{}
		for len(data) > 0 {
			item, rest, err := pop(data, depth+1)
			if err != nil {
				return nil, err
			}
			list = append(list, item)
			data = rest
		}
		return list, nil
	case '}':
		if depth >= maxDepth {
			return nil, syntaxErrorf("not a tnetstring: nesting deeper than %d levels", maxDepth)
		}
		d := &Dict{}
		for len(data) > 0 {
			k, rest, err := pop(data, depth+1)
			if err != nil {
				return nil, err
			}
			var key string
			var bytesKey bool
			switch k := k.(type) {
			case string:
				key = k
			case []byte:
				key, bytesKey = string(k), true
			default:
				return nil, syntaxErrorf("not a tnetstring: dictionary key is %T, not a string", k)
			}
			if len(rest) == 0 {
				// mitmproxy fails here too, with an IndexError from pop.
				return nil, syntaxErrorf("not a tnetstring: dictionary key %q has no value", key)
			}
			v, rest, err := pop(rest, depth+1)
			if err != nil {
				return nil, err
			}
			if i := d.find(key); i >= 0 && d.entries[i].bytesKey != bytesKey {
				return nil, syntaxErrorf("not a tnetstring: dictionary has both a byte-string and a text key %q, which this decoder cannot hold apart", key)
			}
			if bytesKey {
				d.SetBytesKey(key, v)
			} else {
				d.Set(key, v)
			}
			data = rest
		}
		return d, nil
	}
	return nil, syntaxErrorf("unknown type tag: %d", tag)
}

// parseInt parses an integer payload: an optional sign and decimal digits.
// Values outside the int64 range become *big.Int, since Python integers are
// unbounded.
func parseInt(data []byte) (any, error) {
	s := string(data)
	n, err := strconv.ParseInt(s, 10, 64)
	if err == nil {
		return n, nil
	}
	if errors.Is(err, strconv.ErrRange) {
		digits := len(s)
		if s[0] == '-' || s[0] == '+' {
			digits--
		}
		if digits > maxIntDigits {
			return nil, syntaxErrorf("not a tnetstring: integer literal has %d digits, more than the limit of %d", digits, maxIntDigits)
		}
		if b, ok := new(big.Int).SetString(s, 10); ok {
			return b, nil
		}
	}
	return nil, syntaxErrorf("not a tnetstring: invalid integer literal: %s", quote(data))
}

// parseFloat parses a float payload. Like Python's float(), it accepts
// "inf", "nan" and "infinity" in any case, saturates out-of-range values to
// an infinity or zero, and rejects hexadecimal floats, which Go's strconv
// would accept. Unlike Python, it rejects surrounding whitespace and digit
// separators; mitmproxy never writes either.
func parseFloat(data []byte) (any, error) {
	if bytes.ContainsAny(data, "xX") {
		return nil, syntaxErrorf("not a tnetstring: invalid float literal: %s", quote(data))
	}
	f, err := strconv.ParseFloat(string(data), 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, syntaxErrorf("not a tnetstring: invalid float literal: %s", quote(data))
	}
	return f, nil
}
