// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package tnetstring implements mitmproxy's dialect of typed netstrings, the
// serialisation format of .mitm flow files.
//
// A tnetstring is a length-prefixed payload followed by a one-byte type tag:
//
//	11:hello world,
//	5:12345#
//	19:5:12345#4:true!1:0#]
//
// Values map to Go types as follows:
//
//	tag  meaning             Go type written        Go type read
//	,    byte string         []byte                 []byte
//	;    UTF-8 text          string                 string
//	#    integer             int64 (any int kind),  int64, or *big.Int when
//	                         *big.Int               the value overflows int64
//	^    float               float64, float32       float64
//	!    boolean             bool                   bool
//	~    null                nil                    nil
//	]    list                []any                  []any
//	}    dictionary          *Dict                  *Dict
//
// The ; tag is mitmproxy's extension: the original tnetstring specification
// has only byte strings. Dictionary keys may be either, as older flow files
// and addon metadata use byte-string keys; a [Dict] remembers the kind of
// each key and writes it back with the same tag.
//
// The writer reproduces mitmproxy's output byte for byte. Python builds the
// output right to left, so dictionary entries appear in reverse insertion
// order; floats are written as Python's repr writes them (see [FormatFloat]).
// The reader returns dictionary entries in file order.
package tnetstring

import (
	"errors"
	"fmt"
)

// maxDepth bounds the nesting of lists and dictionaries in both directions.
//
// mitmproxy's reader and writer are recursive and stop at Python's default
// recursion limit of 1000 frames, so no file mitmproxy writes nests deeper.
// The bound keeps hostile input and self-referencing values from exhausting
// the goroutine stack.
const maxDepth = 1000

// maxIntDigits is the longest integer literal accepted or written, matching
// the default limit of Python's int/str conversion (sys.int_info.
// default_max_str_digits). Parsing longer literals costs super-linear time.
const maxIntDigits = 4300

// SyntaxError reports malformed tnetstring input. Its message follows the
// wording of mitmproxy's reader.
type SyntaxError struct {
	msg string
}

// Error implements the error interface.
func (e *SyntaxError) Error() string { return e.msg }

func syntaxErrorf(format string, args ...any) error {
	return &SyntaxError{msg: fmt.Sprintf(format, args...)}
}

// ErrUnsupportedType is returned, wrapped, when a value has no tnetstring
// representation.
var ErrUnsupportedType = errors.New("tnetstring: unserializable value")

// quoteLimit is the number of input bytes quoted in a SyntaxError message.
const quoteLimit = 32

// quote renders b for an error message, truncated to quoteLimit bytes.
func quote(b []byte) string {
	if len(b) > quoteLimit {
		return fmt.Sprintf("%q...", b[:quoteLimit])
	}
	return fmt.Sprintf("%q", b)
}
