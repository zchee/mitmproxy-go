// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tnetstring_test

import (
	"fmt"

	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
)

func ExampleDumps() {
	for _, v := range []any{[]byte("hello world"), int64(12345), []any{int64(12345), true, int64(0)}} {
		b, err := tnetstring.Dumps(v)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", b)
	}
	// Output:
	// 11:hello world,
	// 5:12345#
	// 19:5:12345#4:true!1:0#]
}

func ExampleDumps_dictOrder() {
	d := &tnetstring.Dict{}
	d.Set("a", int64(1))
	d.Set("b", int64(2))
	b, err := tnetstring.Dumps(d)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", b)
	// Output:
	// 16:1:b;1:2#1:a;1:1#}
}

func ExampleLoads() {
	v, err := tnetstring.Loads([]byte("16:1:b;1:2#1:a;1:1#}"))
	if err != nil {
		panic(err)
	}
	for k, val := range v.(*tnetstring.Dict).All() {
		fmt.Println(k, val)
	}
	// Output:
	// b 2
	// a 1
}
