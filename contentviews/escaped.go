// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"math"

	"github.com/zchee/mitmproxy-go/internal/strutil"
)

// escapedViewText escapes data as the Python views display bytes, charging
// the escaped size as output before building it.
func escapedViewText(data []byte, stage string, budget *viewBudget) (string, error) {
	var size uint64
	for _, b := range data {
		switch {
		case b == '\\' || b == '\t' || b == '\n' || b == '\r':
			size += 2
		case b < 0x20 || b >= 0x7f:
			size += 4
		default:
			size++
		}
	}
	if size > math.MaxUint64-1 {
		return "", budget.refusal(stage, "output bytes", budget.output, size, budget.limits.OutputBytes)
	}
	if err := budget.chargeOutput(stage, size); err != nil {
		return "", err
	}
	return strutil.BytesToEscapedStr(data, false, false), nil
}
