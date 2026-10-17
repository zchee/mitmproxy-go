// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import "github.com/zchee/mitmproxy-go/internal/strutil"

func escapedViewBytes(data []byte, budget *viewBudget) (string, error) {
	size := 0
	for _, b := range data {
		count := 1
		switch {
		case b == '\\' || b == '\t' || b == '\n' || b == '\r':
			count = 2
		case b < 0x20 || b >= 0x7f:
			count = 4
		}
		if count > maxViewBytes-size {
			return "", &LimitError{View: budget.view, Stage: "escape", Bound: "output bytes"}
		}
		size += count
	}
	if err := budget.reserveNodes(1, "escaped scalar"); err != nil {
		return "", err
	}
	if err := budget.reserveBytes(size, "escape"); err != nil {
		return "", err
	}
	return strutil.BytesToEscapedStr(data, false, false), nil
}
