// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package emoji holds the flow-marker shortcodes of mitmproxy's
// mitmproxy/utils/emoji.py: every name a flow may be marked with and the
// character it is rendered as. The table also contains plain single
// characters, such as "X" and the digits, which mark a flow with that
// character itself.
package emoji

import "slices"

// Names returns every marker shortcode in upstream's order. The returned
// slice is owned by the caller.
func Names() []string { return slices.Clone(names) }

// Char returns the character the marker shortcode name is rendered as, and
// whether the name is in the table.
func Char(name string) (string, bool) {
	c, ok := chars[name]
	return c, ok
}

var (
	names = func() []string {
		ns := make([]string, len(table))
		for i, e := range table {
			ns[i] = e[0]
		}
		return ns
	}()

	chars = func() map[string]string {
		m := make(map[string]string, len(table))
		for _, e := range table {
			m[e[0]] = e[1]
		}
		return m
	}()
)
