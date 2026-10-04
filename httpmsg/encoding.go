// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/encoding/ianaindex"

	netencoding "github.com/zchee/mitmproxy-go/internal/netutil/encoding"
)

// ErrContentEncoding is returned when a message names a Content-Encoding
// that cannot be applied to its body.
var ErrContentEncoding = errors.New("invalid content-encoding")

// decodeContent removes the content coding enc from data.
func decodeContent(data []byte, enc string) ([]byte, error) {
	out, err := netencoding.Decode(data, enc)
	if err != nil {
		return nil, fmt.Errorf("%w %q: %w", ErrContentEncoding, enc, err)
	}
	return out, nil
}

// encodeContent applies the content coding enc to data.
func encodeContent(data []byte, enc string) ([]byte, error) {
	out, err := netencoding.Encode(data, enc)
	if err != nil {
		return nil, fmt.Errorf("%w %q: %w", ErrContentEncoding, enc, err)
	}
	return out, nil
}

// normalizeCharset maps the spellings Python's codec registry accepts for a
// character set to one canonical name.
func normalizeCharset(enc string) string {
	e := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(enc)), "_", "-")
	switch e {
	case "utf8", "utf-8", "u8", "utf", "cp65001":
		return "utf-8"
	case "utf-8-sig", "utf8-sig":
		return "utf-8-sig"
	case "latin-1", "latin1", "latin", "l1", "iso-8859-1", "iso8859-1", "8859", "cp819", "iso-ir-100", "iso-8859-1:1987":
		return "latin-1"
	case "ascii", "us-ascii", "646", "us":
		return "ascii"
	case "utf-16", "utf16", "u16":
		return "utf-16"
	case "utf-16le", "utf-16-le":
		return "utf-16le"
	case "utf-16be", "utf-16-be":
		return "utf-16be"
	case "utf-32", "utf32", "u32":
		return "utf-32"
	case "utf-32le", "utf-32-le":
		return "utf-32le"
	case "utf-32be", "utf-32-be":
		return "utf-32be"
	}
	return e
}

// decodeText decodes body bytes in the character set enc, strictly: any
// byte sequence invalid in that character set is an error.
func decodeText(b []byte, enc string) (string, error) {
	cs := normalizeCharset(enc)
	fail := func() (string, error) {
		return "", fmt.Errorf("cannot decode body as %s", enc)
	}
	switch cs {
	case "utf-8-sig":
		b = trimPrefix(b, "\xef\xbb\xbf")
		fallthrough
	case "utf-8":
		if !utf8.Valid(b) {
			return fail()
		}
		return string(b), nil
	case "latin-1":
		var s strings.Builder
		s.Grow(len(b))
		for _, c := range b {
			s.WriteRune(rune(c))
		}
		return s.String(), nil
	case "ascii":
		for _, c := range b {
			if c >= 0x80 {
				return fail()
			}
		}
		return string(b), nil
	case "utf-16", "utf-16le", "utf-16be":
		order, ok := byteOrder(cs, b, "\xff\xfe", "\xfe\xff")
		if !ok || len(b)%2 != 0 {
			return fail()
		}
		if cs == "utf-16" {
			b = b[min(len(b), 2):]
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = order.Uint16(b[2*i:])
		}
		// utf16.Decode turns unpaired surrogates into U+FFFD; a strict
		// codec rejects them instead.
		for i := 0; i < len(u); i++ {
			switch c := u[i]; {
			case c >= 0xd800 && c < 0xdc00 && i+1 < len(u) && u[i+1] >= 0xdc00 && u[i+1] < 0xe000:
				i++
			case c >= 0xd800 && c < 0xe000:
				return fail()
			}
		}
		return string(utf16.Decode(u)), nil
	case "utf-32", "utf-32le", "utf-32be":
		order, ok := byteOrder(cs, b, "\xff\xfe\x00\x00", "\x00\x00\xfe\xff")
		if !ok || len(b)%4 != 0 {
			return fail()
		}
		if cs == "utf-32" {
			b = b[min(len(b), 4):]
		}
		var s strings.Builder
		for i := 0; i < len(b); i += 4 {
			r := rune(order.Uint32(b[i:]))
			if !utf8.ValidRune(r) {
				return fail()
			}
			s.WriteRune(r)
		}
		return s.String(), nil
	}
	return decodeLegacy(b, enc)
}

// byteOrder picks the byte order for a UTF-16 or UTF-32 codec name. The
// unmarked codec reads a byte order mark and defaults to little endian, as
// Python does on every platform it supports.
func byteOrder(cs string, b []byte, leBOM, beBOM string) (binary.ByteOrder, bool) {
	switch {
	case strings.HasSuffix(cs, "le"):
		return binary.LittleEndian, true
	case strings.HasSuffix(cs, "be"):
		return binary.BigEndian, true
	case strings.HasPrefix(string(b), beBOM):
		return binary.BigEndian, true
	case strings.HasPrefix(string(b), leBOM):
		return binary.LittleEndian, true
	}
	// Python's unmarked codec does not strip anything when there is no
	// mark, so the caller must not drop leading bytes either.
	return binary.LittleEndian, len(b) == 0
}

func trimPrefix(b []byte, prefix string) []byte {
	if strings.HasPrefix(string(b), prefix) {
		return b[len(prefix):]
	}
	return b
}

// encodeText encodes s in the character set enc, failing when s contains a
// character the set cannot represent.
func encodeText(s, enc string) ([]byte, error) {
	cs := normalizeCharset(enc)
	fail := func() ([]byte, error) {
		return nil, fmt.Errorf("cannot encode text as %s", enc)
	}
	// Bytes that are not valid UTF-8 stand for the surrogate escapes
	// Python uses for undecodable input, which no codec encodes strictly.
	if !utf8.ValidString(s) {
		return fail()
	}
	switch cs {
	case "utf-8":
		return []byte(s), nil
	case "utf-8-sig":
		return append([]byte("\xef\xbb\xbf"), s...), nil
	case "latin-1", "ascii":
		limit := rune(0xff)
		if cs == "ascii" {
			limit = 0x7f
		}
		out := make([]byte, 0, len(s))
		for _, r := range s {
			if r > limit || r == utf8.RuneError {
				return fail()
			}
			out = append(out, byte(r))
		}
		return out, nil
	case "utf-16", "utf-16le", "utf-16be":
		var order binary.AppendByteOrder = binary.LittleEndian
		var out []byte
		switch cs {
		case "utf-16":
			out = []byte("\xff\xfe")
		case "utf-16be":
			order = binary.BigEndian
		}
		for _, u := range utf16.Encode([]rune(s)) {
			out = order.AppendUint16(out, u)
		}
		return out, nil
	case "utf-32", "utf-32le", "utf-32be":
		var order binary.AppendByteOrder = binary.LittleEndian
		var out []byte
		switch cs {
		case "utf-32":
			out = []byte("\xff\xfe\x00\x00")
		case "utf-32be":
			order = binary.BigEndian
		}
		for _, r := range s {
			out = order.AppendUint32(out, uint32(r))
		}
		return out, nil
	}
	return encodeLegacy(s, enc)
}

// pythonAliases maps Python codec spellings that neither the IANA nor the
// WHATWG index knows to a label they do.
var pythonAliases = map[string]string{
	"cp932": "windows-31j", "ms932": "windows-31j", "mskanji": "windows-31j", "ms-kanji": "windows-31j",
	"cp936": "gbk", "ms936": "gbk",
	"cp949": "euc-kr", "ms949": "euc-kr", "uhc": "euc-kr",
	"cp950": "big5", "ms950": "big5",
}

// iso8859RE matches Python's spellings of ISO 8859 parts, such as
// "iso8859_7" or "iso_8859-2".
var iso8859RE = regexp.MustCompile(`^iso[-_]?8859[-_](\d+)$`)

// windowsCPRE matches Python's "cp125x" names for the Windows code pages.
var windowsCPRE = regexp.MustCompile(`^cp(125\d)$`)

// lookupCharset resolves a character set label to an encoding: first
// through the IANA registry, then through the WHATWG labels browsers use,
// trying the label as given and in the spellings Python's codec registry
// accepts. It reports false when no index knows the label.
func lookupCharset(label string) (encoding.Encoding, bool) {
	l := strings.ToLower(strings.TrimSpace(label))
	candidates := []string{l, strings.ReplaceAll(l, "_", "-")}
	if a, ok := pythonAliases[candidates[1]]; ok {
		candidates = append(candidates, a)
	}
	if m := iso8859RE.FindStringSubmatch(l); m != nil {
		candidates = append(candidates, "iso-8859-"+m[1])
	}
	if m := windowsCPRE.FindStringSubmatch(l); m != nil {
		candidates = append(candidates, "windows-"+m[1])
	}
	for _, c := range candidates {
		// The IANA index returns a nil encoding without an error for names
		// it knows but cannot convert, such as UTF-7.
		if e, err := ianaindex.IANA.Encoding(c); err == nil && e != nil {
			return e, true
		}
	}
	for _, c := range candidates {
		if e, err := htmlindex.Get(c); err == nil && e != nil {
			return e, true
		}
	}
	return nil, false
}

// decodeLegacy decodes b in a character set from the encoding indexes,
// strictly. The x/text decoders substitute U+FFFD for invalid input where
// Python's strict codecs raise, so a result containing U+FFFD is accepted
// only when encoding it again reproduces b.
func decodeLegacy(b []byte, label string) (string, error) {
	e, ok := lookupCharset(label)
	if !ok {
		return "", fmt.Errorf("unsupported character set %q", label)
	}
	out, err := e.NewDecoder().Bytes(b)
	if err != nil {
		return "", fmt.Errorf("cannot decode body as %s: %w", label, err)
	}
	if bytes.ContainsRune(out, utf8.RuneError) {
		again, err := e.NewEncoder().Bytes(out)
		if err != nil || !bytes.Equal(again, b) {
			return "", fmt.Errorf("cannot decode body as %s", label)
		}
	}
	return string(out), nil
}

// encodeLegacy encodes s in a character set from the encoding indexes,
// failing when s holds a character the set cannot represent.
func encodeLegacy(s, label string) ([]byte, error) {
	e, ok := lookupCharset(label)
	if !ok {
		return nil, fmt.Errorf("unsupported character set %q", label)
	}
	out, err := e.NewEncoder().Bytes([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("cannot encode text as %s: %w", label, err)
	}
	return out, nil
}
