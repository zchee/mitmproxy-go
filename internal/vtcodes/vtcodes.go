// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package vtcodes detects whether an output supports virtual terminal escape
// codes and renders the ANSI styles mitmproxy prints with. It ports
// mitmproxy's mitmproxy/utils/vt_codes.py and the attributes of its vendored
// click.style (mitmproxy/contrib/click).
package vtcodes

import (
	"io"
	"os"
	"strconv"
	"strings"
)

// EnsureSupported reports whether w supports virtual terminal escape codes,
// as upstream's vt_codes.ensure_supported decides: w must be a terminal
// file. On Windows it must be the process's stdout or stderr, and virtual
// terminal processing is enabled on the console as a side effect.
func EnsureSupported(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return isSupported(f)
}

// Columns returns the terminal width of f, or false when f is not a
// terminal.
func Columns(f *os.File) (int, bool) {
	if f == nil {
		return 0, false
	}
	return columns(f)
}

// colors are the ANSI foreground codes of click's color names.
var colors = map[string]int{
	"black": 30, "red": 31, "green": 32, "yellow": 33,
	"blue": 34, "magenta": 35, "cyan": 36, "white": 37, "reset": 39,
	"bright_black": 90, "bright_red": 91, "bright_green": 92, "bright_yellow": 93,
	"bright_blue": 94, "bright_magenta": 95, "bright_cyan": 96, "bright_white": 97,
}

// Style holds the text attributes mitmproxy passes to click.style: a
// foreground color name and tri-state bold, dim and blink flags. A nil flag
// means the attribute is left alone; false emits the attribute's explicit
// reset code, exactly as click does.
type Style struct {
	// FG is a click color name, such as "yellow" or "bright_blue". Empty
	// means no foreground color.
	FG string
	// Bold switches bold on (code 1) or off (code 22).
	Bold *bool
	// Dim switches dim on (code 2) or off (code 22).
	Dim *bool
	// Blink switches blinking on (code 5) or off (code 25).
	Blink *bool
}

// IsZero reports whether no attribute is set.
func (s Style) IsZero() bool {
	return s.FG == "" && s.Bold == nil && s.Dim == nil && s.Blink == nil
}

// Render returns text wrapped in the style's escape codes, always followed
// by a reset-all code, as click.style renders with reset=True. An unknown
// color name panics: color names are compile-time constants of the callers.
func (s Style) Render(text string) string {
	var b strings.Builder
	if s.FG != "" {
		code, ok := colors[s.FG]
		if !ok {
			panic("vtcodes: unknown color " + strconv.Quote(s.FG))
		}
		b.WriteString("\x1b[")
		b.WriteString(strconv.Itoa(code))
		b.WriteString("m")
	}
	onOff(&b, s.Bold, 1, 22)
	onOff(&b, s.Dim, 2, 22)
	onOff(&b, s.Blink, 5, 25)
	b.WriteString(text)
	b.WriteString("\x1b[0m")
	return b.String()
}

// onOff writes the escape code for a tri-state attribute.
func onOff(b *strings.Builder, v *bool, on, off int) {
	if v == nil {
		return
	}
	code := off
	if *v {
		code = on
	}
	b.WriteString("\x1b[")
	b.WriteString(strconv.Itoa(code))
	b.WriteString("m")
}
