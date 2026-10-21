// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package style provides safe terminal text and the console's semantic palette.
package style

import (
	"strings"
	"unicode"
	"unicode/utf8"

	lipgloss "charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/rivo/uniseg"

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

// PreviousGrapheme returns the preceding grapheme boundary as a rune index.
// Out-of-range cursors are clamped; a cursor inside a cluster moves to its start.
func PreviousGrapheme(text string, cursor int) int {
	cursor = min(max(cursor, 0), utf8.RuneCountInString(text))
	previous, position := 0, 0
	clusters := uniseg.NewGraphemes(text)
	for clusters.Next() {
		position += utf8.RuneCountInString(clusters.Str())
		if position >= cursor {
			return previous
		}
		previous = position
	}
	return previous
}

// NextGrapheme returns the next grapheme boundary as a rune index.
// Out-of-range cursors are clamped; a cursor inside a cluster moves to its end.
func NextGrapheme(text string, cursor int) int {
	cursor = min(max(cursor, 0), utf8.RuneCountInString(text))
	position := 0
	clusters := uniseg.NewGraphemes(text)
	for clusters.Next() {
		position += utf8.RuneCountInString(clusters.Str())
		if position > cursor {
			return position
		}
	}
	return position
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
