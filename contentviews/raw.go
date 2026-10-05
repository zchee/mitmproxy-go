// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"strings"
	"unicode/utf8"
)

// Raw displays UTF-8 text, replacing invalid bytes with backslash escapes.
type Raw struct{}

// Name returns the display name.
func (Raw) Name() string { return "Raw" }

// SyntaxHighlight disables syntax highlighting.
func (Raw) SyntaxHighlight() string { return "none" }

// RenderPriority supplies the default text fallback priority.
func (Raw) RenderPriority([]byte, Metadata) float64 { return 0.1 }

// Prettify decodes UTF-8 using Python's backslashreplace error policy.
func (Raw) Prettify(data []byte, _ Metadata) (string, error) {
	if utf8.Valid(data) {
		return string(data), nil
	}
	var text strings.Builder
	text.Grow(len(data))
	const hex = "0123456789abcdef"
	for len(data) > 0 {
		r, n := utf8.DecodeRune(data)
		if r == utf8.RuneError && n == 1 {
			text.WriteString(`\x`)
			text.WriteByte(hex[data[0]>>4])
			text.WriteByte(hex[data[0]&15])
		} else {
			text.Write(data[:n])
		}
		data = data[n:]
	}
	return text.String(), nil
}
