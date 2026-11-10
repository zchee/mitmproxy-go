// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package regex

// IsBacktracking reports whether m runs on the regexp2 fallback engine.
func IsBacktracking(m Matcher) bool {
	if p, ok := m.(*Pattern); ok {
		return p.bt != nil
	}
	_, ok := m.(*backtrackMatcher)
	return ok
}
