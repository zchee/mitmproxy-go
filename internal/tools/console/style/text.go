// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package style provides safe terminal text and the console's semantic palette.
package style

import (
	"strings"
	"unicode"

	lipgloss "charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/zchee/mitmproxy-go/internal/strutil"
)

// Escape removes terminal control characters before trusted styling is added.
// Line feeds are preserved for body rendering; carriage returns and C1 controls
// are never allowed to move the cursor or introduce terminal commands.
func Escape(text string) string {
	text = strutil.EscapeControlCharacters(strings.ToValidUTF8(text, "�"), true)
	return strings.Map(func(r rune) rune {
		if r != '\n' && unicode.IsControl(r) {
			return '.'
		}
		return r
	}, text)
}

// Width returns the display-cell width, ignoring trusted ANSI styling.
func Width(text string) int { return lipgloss.Width(text) }

// Truncate clips trusted styled text at a grapheme boundary using an ellipsis.
func Truncate(text string, width int) string {
	if width <= 0 {
		return ""
	}
	return ansi.Truncate(text, width, "…")
}

// Fit truncates and pads trusted text to an exact cell width.
func Fit(text string, width int) string {
	text = Truncate(text, width)
	return text + strings.Repeat(" ", max(0, width-Width(text)))
}
