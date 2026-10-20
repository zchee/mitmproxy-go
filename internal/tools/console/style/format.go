// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package style

import (
	"fmt"
	"math"
	"strings"

	"github.com/zchee/mitmproxy-go/internal/human"
)

// FormatDuration returns the upstream duration text and logarithmic gradient tag.
func FormatDuration(seconds float64) (string, string) {
	index := int(99 - 100*min(math.Log2(max(1, 1000*seconds))/12, 0.99))
	return human.PrettyDuration(seconds), fmt.Sprintf("gradient_%02d", index)
}

// KeyValue is one plain-text reference row; empty values still retain their key.
type KeyValue struct{ Key, Value string }

// FormatKeyValues aligns escaped key/value columns using display-cell widths.
func FormatKeyValues(entries []KeyValue, indent int) string {
	keyWidth := 0
	for _, entry := range entries {
		keyWidth = max(keyWidth, Width(Escape(entry.Key)))
	}
	keyWidth = min(keyWidth, 30)
	var rows []string
	for _, entry := range entries {
		rows = append(rows, strings.Repeat(" ", max(0, indent))+Fit(Escape(entry.Key), keyWidth)+"  "+Escape(entry.Value))
	}
	return strings.Join(rows, "\n")
}
