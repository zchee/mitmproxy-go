// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package omap_test

import (
	"fmt"

	"github.com/zchee/mitmproxy-go/omap"
)

func Example() {
	var m omap.Map[int] // The zero value is ready to use.
	m.Set("b", 1)
	m.Set("a", 2)
	m.SetBytesKey("raw", 3)

	// Overwriting keeps the position; deleting and re-adding moves to the end.
	m.Set("b", 10)
	m.Delete("a")
	m.Set("a", 20)

	for k, v := range m.All() {
		fmt.Println(k, v, m.IsBytesKey(k))
	}
	fmt.Println(m.String())
	// Output:
	// b 10 false
	// raw 3 true
	// a 20 false
	// {"b": 10, b"raw": 3, "a": 20}
}
