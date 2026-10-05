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
	meta := state.NewMap(6)
	meta.Set("owner", "addon-a")
	meta.Set("hits", int64(3))
	meta.Set("token", []byte{0xde, 0xad})
	huge, _ := new(big.Int).SetString("18446744073709551616", 10) // 2**64
	meta.Set("serial", huge)
	meta.Set("ports", []any{int64(80), int64(443)})
	tags := state.NewMap(1)
	tags.SetBytesKey("raw", true)
	meta.Set("tags", tags)
	fmt.Println(meta)

	// Read it back. Every accessor consumes its key, so Finish can report
	// both type errors and keys nobody read. Values inside a list are read
	// with the conversion functions.
	d := state.NewDecoder(state.CopyMap(meta), "Metadata")
	fmt.Printf("%s %d %x\n", d.String("owner"), d.Int("hits"), d.Bytes("token"))
	fmt.Println(d.Any("serial"))
	ports, err := state.ListOf(d.List("ports"), state.AsInt)
	fmt.Println(ports, err)
	fmt.Println(d.Dict("tags").IsBytesKey("raw"))
	fmt.Println(d.Finish())

	// The typed accessors hold integers as int64 and refuse a larger one.
	d = state.NewDecoder(state.CopyMap(meta), "Metadata")
	d.Int("serial")
	fmt.Println(d.Finish())

	// Keys left unread are reported as upstream's set_state reports them.
	d = state.NewDecoder(state.CopyMap(meta), "Metadata")
	d.String("owner")
	fmt.Println(d.Finish())

	// A value of the wrong type is named by its Python type.
	_, err = state.ListOf([]any{int64(80), "443"}, state.AsInt)
	fmt.Println(err)

	// Equal compares as Python's == does: key order does not matter, and an
	// integer equals a float of the same value.
	a := state.NewMap(2)
	a.Set("x", int64(1))
	a.Set("y", 2.0)
	b := state.NewMap(2)
	b.Set("y", int64(2))
	b.Set("x", 1.0)
	fmt.Println(state.Equal(a, b), state.Equal(meta, state.CopyMap(meta)))
	// Output:
	// {"owner": addon-a, "hits": 3, "token": [222 173], "serial": 18446744073709551616, "ports": [80 443], "tags": {b"raw": true}}
	// addon-a 3 dead
	// 18446744073709551616
	// [80 443] <nil>
	// true
	// <nil>
	// Metadata.set_state: field "serial": integer 18446744073709551616 does not fit in 64 bits
	// unexpected fields in Metadata.set_state: [hits token serial ports tags]
	// item 1: expected int, got str
	// true true
}
