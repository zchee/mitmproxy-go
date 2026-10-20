// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowview

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// Search is the independent case-sensitive search state of one tab.
type Search struct {
	Term    string
	Focus   int
	Matched bool
}

// Find searches after the current row, wrapping once in the requested direction.
// No match clears the highlight without changing focus.
func (s *Search) Find(lines []string, backwards bool) bool {
	s.Matched = false
	if s.Term == "" || len(lines) == 0 {
		return false
	}
	s.Focus = min(max(0, s.Focus), len(lines)-1)
	for distance := 1; distance <= len(lines); distance++ {
		offset := (s.Focus + distance) % len(lines)
		if backwards {
			offset = (s.Focus - distance + len(lines)) % len(lines)
		}
		if strings.Contains(ansi.Strip(lines[offset]), s.Term) {
			s.Focus = offset
			s.Matched = true
			return true
		}
	}
	return false
}
