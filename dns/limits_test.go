// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func expansionMessage(count int) []byte {
	data := []byte{0, 42, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(data[4:], uint16(count))
	for _, length := range []int{63, 63, 63, 61} {
		data = append(data, byte(length))
		data = append(data, bytes.Repeat([]byte{'a'}, length)...)
	}
	data = append(data, 0, 0, 1, 0, 1)
	for range count - 1 {
		data = append(data, 0xc0, 12, 0, 1, 0, 1)
	}
	return data
}

func TestCodecBounds(t *testing.T) {
	tests := map[string]struct {
		data []byte
	}{
		"oversized wire":       {data: make([]byte, maxWireSize+1)},
		"compressed expansion": {data: expansionMessage(5000)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			message, err := Unpack(tt.data, nil)
			if _, ok := errors.AsType[*limitError](err); !ok || message != nil {
				t.Fatalf("Unpack = %+v, %v; want typed limit error and nil message", message, err)
			}
		})
	}
	message := &Message{Answers: []ResourceRecord{{Type: TypeNULL, Data: make([]byte, maxWireSize-23)}}}
	wire, err := Pack(message)
	if err != nil || len(wire) != maxWireSize {
		t.Fatalf("maximum wire = %d bytes, %v", len(wire), err)
	}
	message.Answers[0].Data = append(message.Answers[0].Data, 0)
	if _, err := Pack(message); err == nil {
		t.Fatal("oversized packed message accepted")
	}
	// Counts do not cause allocation before the first item can be parsed.
	short := make([]byte, 12)
	binary.BigEndian.PutUint16(short[4:], 65535)
	if _, err := Unpack(short, nil); err == nil {
		t.Fatal("question count without question bytes accepted")
	}
}

func TestCompressionPointerDirection(t *testing.T) {
	data := []byte{0, 42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 18, 0, 1, 0, 1, 0}
	if _, err := Unpack(data, nil); err == nil {
		t.Fatal("forward compression pointer accepted")
	}
}
