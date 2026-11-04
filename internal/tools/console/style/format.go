// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package style

import (
	"fmt"
	"math"

	"github.com/zchee/mitmproxy-go/internal/human"
)

// FormatDuration returns the upstream duration text and logarithmic gradient tag.
func FormatDuration(seconds float64) (string, string) {
	index := int(99 - 100*min(math.Log2(max(1, 1000*seconds))/12, 0.99))
	return human.PrettyDuration(seconds), fmt.Sprintf("gradient_%02d", index)
}
