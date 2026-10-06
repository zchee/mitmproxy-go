// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2/hpack"
)

func TestHeaderAssembly(t *testing.T) {
	tests := map[string]struct {
		fields   []hpack.HeaderField
		validate bool
		wantErr  bool
	}{
		"success: ordered repeated fields":               {fields: []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":path", Value: "/"}, {Name: "x-order", Value: "one"}, {Name: "x-order", Value: "two"}}, validate: true},
		"success: validation bypass preserves uppercase": {fields: []hpack.HeaderField{{Name: "X-Foo", Value: " :) "}}},
		"error: uppercase":                               {fields: []hpack.HeaderField{{Name: "X-Foo", Value: "bar"}}, validate: true, wantErr: true},
		"error: duplicate pseudo header":                 {fields: []hpack.HeaderField{{Name: ":status", Value: "418"}, {Name: ":status", Value: "418"}}, validate: true, wantErr: true},
		"error: pseudo header after ordinary header":     {fields: []hpack.HeaderField{{Name: "foo", Value: "bar"}, {Name: ":status", Value: "200"}}, validate: true, wantErr: true},
		"error: connection header":                       {fields: []hpack.HeaderField{{Name: "transfer-encoding", Value: "chunked"}}, validate: true, wantErr: true},
		"error: oversized field":                         {fields: []hpack.HeaderField{{Name: "x-big", Value: string(bytes.Repeat([]byte{'a'}, maxHeaderBytes+1))}}, wantErr: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var block bytes.Buffer
			encoder := hpack.NewEncoder(&block)
			for _, field := range test.fields {
				if err := encoder.WriteField(field); err != nil {
					t.Fatal(err)
				}
			}
			assembler := newHeaderAssembly(test.validate)
			var result []hpack.HeaderField
			var err error
			for i, b := range block.Bytes() {
				result, err = assembler.fragment(1, i == 0, i == block.Len()-1, []byte{b})
				if err != nil {
					break
				}
			}
			if (err != nil) != test.wantErr {
				t.Fatalf("assembly error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr {
				if diff := cmp.Diff(test.fields, result); diff != "" {
					t.Fatalf("ordered headers (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestHeaderAssemblyInvalidOrder(t *testing.T) {
	tests := map[string]struct {
		start  bool
		stream uint32
	}{
		"error: continuation without head":       {stream: 1},
		"error: second head before continuation": {start: true, stream: 1},
		"error: wrong stream continuation":       {stream: 3},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			a := newHeaderAssembly(false)
			if name != "error: continuation without head" {
				if _, err := a.fragment(1, true, false, []byte{0x82}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := a.fragment(test.stream, test.start, true, []byte{0x84}); err == nil {
				t.Fatal("invalid assembly order accepted")
			}
		})
	}
}

func FuzzHeaderAssembly(f *testing.F) {
	f.Add([]byte{0x82, 0x86, 0x84, 0x41, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}, uint8(3))
	f.Add([]byte{0x88}, uint8(1))
	f.Add([]byte{0xff}, uint8(1))
	f.Add([]byte{}, uint8(0))
	f.Fuzz(func(t *testing.T, block []byte, split uint8) {
		if len(block) > maxHeaderBytes*2 {
			return
		}
		a := newHeaderAssembly(false)
		cut := min(int(split), len(block))
		_, err := a.fragment(1, true, false, block[:cut])
		if err != nil {
			return
		}
		fields, err := a.fragment(1, false, true, block[cut:])
		if err == nil {
			var size int
			for _, field := range fields {
				size += len(field.Name) + len(field.Value) + 32
			}
			if size > maxHeaderBytes {
				t.Fatalf("unbounded header list: %d", size)
			}
		}
	})
}

func TestWindowBudget(t *testing.T) {
	var budget windowBudget
	windows := make([]streamWindow, MaxConcurrentStreams)
	for i := range windows {
		if !budget.reserve(&windows[i]) {
			t.Fatalf("stream %d refused", i)
		}
		if budget.snapshot().Granted > 128<<20 {
			t.Fatal("initial budget exceeded")
		}
	}
	if budget.reserve(new(streamWindow)) {
		t.Fatal("101st initial reservation accepted")
	}
	// Each consumed threshold is evaluated once even when growth is denied.
	for i := range windows {
		for range 4 {
			budget.consume(&windows[i], windows[i].grant/2)
			if budget.snapshot().Granted > 128<<20 {
				t.Fatal("growth exceeded budget")
			}
		}
	}
	if got := budget.snapshot().Granted; got != 128<<20 {
		t.Fatalf("headroom not exhausted: %d", got)
	}
	stalled := &windows[99]
	if stalled.grant != InitialStreamWindow || stalled.consumed != 0 {
		t.Fatalf("denied evaluation retained consumption: %+v", stalled)
	}
	budget.release(&windows[0])
	budget.consume(stalled, 1)
	if stalled.grant != InitialStreamWindow {
		t.Fatal("denied receipt reused after headroom reopened")
	}
	for i := range windows {
		budget.release(&windows[i])
	}
	if got := budget.snapshot(); got.Granted != 0 || got.Maximum != 128<<20 {
		t.Fatalf("released budget = %+v", got)
	}
}
