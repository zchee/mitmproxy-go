// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package filter

import "github.com/zchee/mitmproxy-go/internal/pyrepr"

// pyStr formats a state value the way Python's str() formats the object it
// stands for: a string as itself, everything else as repr(). ~meta matches
// against "key: str(value)" lines.
func pyStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return pyrepr.Value(v)
}
