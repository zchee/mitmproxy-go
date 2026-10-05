// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"encoding/binary"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
	"github.com/zchee/mitmproxy-go/omap"
)

// JSON formats JSON with four-space indentation and Python's scalar semantics.
// Objects retain insertion order, including the position of duplicate names.
// Lone surrogates are preserved as WTF-8, since Go strings can hold their bytes.
// Input nesting is limited to 1024 containers.
type JSON struct{}

// Name returns the registered view name.
func (JSON) Name() string { return "JSON" }

// SyntaxHighlight returns the upstream JSON view's highlighting language.
func (JSON) SyntaxHighlight() string { return "yaml" }

// RenderPriority prefers nonempty JSON media types.
func (JSON) RenderPriority(data []byte, metadata Metadata) float64 {
	if len(data) != 0 && (metadata.ContentType == "application/json-rpc" ||
		strings.HasPrefix(metadata.ContentType, "application/") && strings.HasSuffix(metadata.ContentType, "json")) {
		return 1
	}
	return 0
}

// Prettify decodes JSON and formats it as Python's json.dumps with indent=4.
// Invalid encodings, malformed JSON and excessive nesting return an error.
func (JSON) Prettify(data []byte, _ Metadata) (string, error) {
	data, err := jsonUTF8(data)
	if err != nil {
		return "", err
	}
	data, constants := jsonConstants(data)
	dec := jsontext.NewDecoder(bytes.NewReader(data), jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
	value, err := readJSON(dec, constants, 0)
	if err != nil {
		return "", fmt.Errorf("contentviews: invalid JSON: %w", err)
	}
	if _, err = dec.ReadToken(); !errors.Is(err, io.EOF) {
		return "", errors.New("contentviews: trailing JSON data")
	}
	var out strings.Builder
	writeJSON(&out, value, 0)
	return out.String(), nil
}

// jsonConstants substitutes equal-length valid tokens before using jsontext's
// grammar checks. Python permits these literals; RFC 8259 parsers do not.
func jsonConstants(data []byte) ([]byte, map[int64]string) {
	var constants map[int64]string
	quoted := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			quoted = !quoted
			continue
		}
		if quoted {
			if data[i] == '\\' {
				i++
			}
			continue
		}
		for _, literal := range []string{"NaN", "Infinity", "-Infinity"} {
			end := i + len(literal)
			if !bytes.HasPrefix(data[i:], []byte(literal)) ||
				(i > 0 && !strings.ContainsRune("[,: \t\r\n", rune(data[i-1]))) ||
				(end < len(data) && !strings.ContainsRune(",]} \t\r\n", rune(data[end]))) {
				continue
			}
			if constants == nil {
				data = bytes.Clone(data)
				constants = make(map[int64]string)
			}
			for j := i; j < end-1; j++ {
				data[j] = ' '
			}
			data[end-1] = '0'
			constants[int64(end)] = literal
			i = end - 1
			break
		}
	}
	return data, constants
}

func readJSON(dec *jsontext.Decoder, constants map[int64]string, depth int) (any, error) {
	kind := dec.PeekKind()
	if kind == '{' || kind == '[' {
		if depth >= 1024 {
			return nil, errors.New("nesting exceeds 1024 containers")
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		if kind == '{' {
			object := omap.New[any]()
			for dec.PeekKind() != '}' {
				key, err := dec.ReadValue()
				if err != nil {
					return nil, err
				}
				name := unquoteJSON(key)
				value, err := readJSON(dec, constants, depth+1)
				if err != nil {
					return nil, err
				}
				object.Set(name, value)
			}
			_, err := dec.ReadToken()
			return object, err
		}
		var array []any
		for dec.PeekKind() != ']' {
			value, err := readJSON(dec, constants, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		_, err := dec.ReadToken()
		return array, err
	}
	value, err := dec.ReadValue()
	if err != nil {
		return nil, err
	}
	switch kind {
	case '"':
		return quoteJSON(unquoteJSON(value)), nil
	case '0':
		if literal, ok := constants[dec.InputOffset()]; ok {
			return literal, nil
		}
		text := string(value)
		if strings.ContainsAny(text, ".eE") {
			f, err := strconv.ParseFloat(text, 64)
			if err != nil && !errors.Is(err, strconv.ErrRange) {
				return nil, err
			}
			switch {
			case math.IsInf(f, 1):
				return "Infinity", nil
			case math.IsInf(f, -1):
				return "-Infinity", nil
			default:
				return tnetstring.FormatFloat(f), nil
			}
		}
		if len(strings.TrimPrefix(text, "-")) > 4300 {
			return nil, errors.New("integer exceeds Python's 4300-digit conversion limit")
		}
		if text == "-0" {
			text = "0"
		}
		return text, nil
	default:
		return string(value), nil
	}
}

func writeJSON(out *strings.Builder, value any, depth int) {
	indent := func(level int) { out.WriteString(strings.Repeat("    ", level)) }
	switch value := value.(type) {
	case *omap.Map[any]:
		out.WriteByte('{')
		i := 0
		for key, child := range value.All() {
			if i != 0 {
				out.WriteByte(',')
			}
			out.WriteByte('\n')
			indent(depth + 1)
			out.WriteString(quoteJSON(key))
			out.WriteString(": ")
			writeJSON(out, child, depth+1)
			i++
		}
		if i != 0 {
			out.WriteByte('\n')
			indent(depth)
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, child := range value {
			if i != 0 {
				out.WriteByte(',')
			}
			out.WriteByte('\n')
			indent(depth + 1)
			writeJSON(out, child, depth+1)
		}
		if len(value) != 0 {
			out.WriteByte('\n')
			indent(depth)
		}
		out.WriteByte(']')
	case string:
		out.WriteString(value)
	}
}

// unquoteJSON receives a validated string. Unlike jsontext's string conversion,
// it preserves lone UTF-16 surrogates rather than replacing them with U+FFFD.
func unquoteJSON(raw []byte) string {
	var out []byte
	for i := 1; i < len(raw)-1; i++ {
		if raw[i] != '\\' {
			out = append(out, raw[i])
			continue
		}
		i++
		switch raw[i] {
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			code, _ := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
			i += 4
			r := rune(code)
			if r >= 0xd800 && r <= 0xdbff && i+6 < len(raw) && raw[i+1] == '\\' && raw[i+2] == 'u' {
				low, _ := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
				if low >= 0xdc00 && low <= 0xdfff {
					r = utf16.DecodeRune(r, rune(low))
					i += 6
				}
			}
			out = appendJSONRune(out, r)
		default:
			out = append(out, raw[i])
		}
	}
	return string(out)
}

func quoteJSON(text string) string {
	var out strings.Builder
	out.WriteByte('"')
	for i := range len(text) {
		c := text[i]
		switch c {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteByte(c)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if c < 0x20 {
				out.WriteByte('\\')
				out.WriteString("u00")
				const digits = "0123456789abcdef"
				out.WriteByte(digits[c>>4])
				out.WriteByte(digits[c&15])
			} else {
				out.WriteByte(c)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

func appendJSONRune(out []byte, r rune) []byte {
	if r >= 0xd800 && r <= 0xdfff {
		return append(out, byte(0xe0|r>>12), byte(0x80|(r>>6)&63), byte(0x80|r&63))
	}
	return utf8.AppendRune(out, r)
}

// jsonUTF8 follows Python json.detect_encoding and the surrogatepass codec.
func jsonUTF8(data []byte) ([]byte, error) {
	var order binary.ByteOrder
	width := 1
	switch {
	case bytes.HasPrefix(data, []byte{0, 0, 0xfe, 0xff}):
		order, width, data = binary.BigEndian, 4, data[4:]
	case bytes.HasPrefix(data, []byte{0xff, 0xfe, 0, 0}):
		order, width, data = binary.LittleEndian, 4, data[4:]
	case bytes.HasPrefix(data, []byte{0xfe, 0xff}):
		order, width, data = binary.BigEndian, 2, data[2:]
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}):
		order, width, data = binary.LittleEndian, 2, data[2:]
	case bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}):
		data = data[3:]
	case len(data) >= 4 && data[0] == 0 && data[1] == 0:
		order, width = binary.BigEndian, 4
	case len(data) >= 4 && data[1] == 0 && data[2] == 0 && data[3] == 0:
		order, width = binary.LittleEndian, 4
	case len(data) >= 2 && data[0] == 0:
		order, width = binary.BigEndian, 2
	case len(data) >= 2 && data[1] == 0:
		order, width = binary.LittleEndian, 2
	}
	invalid := errors.New("contentviews: invalid JSON Unicode encoding")
	if width == 1 {
		for i := 0; i < len(data); {
			r, size := utf8.DecodeRune(data[i:])
			if r == utf8.RuneError && size == 1 {
				if i+2 >= len(data) || data[i] != 0xed || data[i+1] < 0xa0 || data[i+1] > 0xbf || data[i+2] < 0x80 || data[i+2] > 0xbf {
					return nil, invalid
				}
				size = 3
			}
			i += size
		}
		return data, nil
	}
	if len(data)%width != 0 {
		return nil, invalid
	}
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i += width {
		var r rune
		if width == 4 {
			code := order.Uint32(data[i:])
			if code > utf8.MaxRune {
				return nil, invalid
			}
			r = rune(code)
		} else {
			r = rune(order.Uint16(data[i:]))
			if r >= 0xd800 && r <= 0xdbff && i+3 < len(data) {
				low := rune(order.Uint16(data[i+2:]))
				if low >= 0xdc00 && low <= 0xdfff {
					r = utf16.DecodeRune(r, low)
					i += 2
				}
			}
		}
		out = appendJSONRune(out, r)
	}
	return out, nil
}
