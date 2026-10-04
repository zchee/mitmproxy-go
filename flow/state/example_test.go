// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package state_test

import (
	"fmt"
	"math/big"

	"github.com/zchee/mitmproxy-go/flow/state"
)

func Example() {
	// Build flow metadata the way an addon would before the flow is saved.
	meta := state.NewMap(4)
	meta.Set("owner", "addon-a")
	meta.Set("hits", int64(3))
	meta.Set("token", []byte{0xde, 0xad})
	huge, _ := new(big.Int).SetString("18446744073709551616", 10) // 2**64
	meta.Set("serial", huge)
	tags := state.NewMap(1)
	tags.SetBytesKey("raw", true)
	meta.Set("tags", tags)
	fmt.Println(meta)

	// Read it back. Every accessor consumes its key, so Finish can report
	// both type errors and keys nobody read.
	d := state.NewDecoder(state.CopyMap(meta), "Metadata")
	fmt.Printf("%s %d %x\n", d.String("owner"), d.Int("hits"), d.Bytes("token"))
	fmt.Println(d.Any("serial"))
	fmt.Println(d.Dict("tags").IsBytesKey("raw"))
	fmt.Println(d.Finish())

	// The typed accessors hold integers as int64 and refuse a larger one.
	d = state.NewDecoder(state.CopyMap(meta), "Metadata")
	d.Int("serial")
	fmt.Println(d.Finish())
	// Output:
	// {"owner": addon-a, "hits": 3, "token": [222 173], "serial": 18446744073709551616, "tags": {b"raw": true}}
	// addon-a 3 dead
	// 18446744073709551616
	// true
	// <nil>
	// Metadata.set_state: field "serial": integer 18446744073709551616 does not fit in 64 bits
}
