// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"encoding/binary"
	"errors"
	"fmt"

	miekg "codeberg.org/miekg/dns"
)

// packHeader isolates the library's header representation from the flow state.
// Record bytes remain opaque: mitmproxy accepts records a typed RR parser rejects.
func packHeader(message *Message) ([]byte, error) {
	if message == nil {
		return nil, errors.New("nil DNS message")
	}
	for _, field := range []struct {
		name  string
		value int
		max   int
	}{
		{"id", message.ID, 65535},
		{"op_code", message.OpCode, 15},
		{"reserved", message.Reserved, 7},
		{"response_code", message.ResponseCode, 15},
		{"question count", len(message.Questions), 65535},
		{"answer count", len(message.Answers), 65535},
		{"authority count", len(message.Authorities), 65535},
		{"additional count", len(message.Additionals), 65535},
	} {
		if field.value < 0 || field.value > field.max {
			return nil, fmt.Errorf("DNS message's %s %d is out of bounds", field.name, field.value)
		}
	}
	wire := miekg.Msg{
		ID:                 uint16(message.ID),
		Opcode:             uint8(message.OpCode),
		Rcode:              uint16(message.ResponseCode),
		Response:           !message.Query,
		Authoritative:      message.AuthoritativeAnswer,
		Truncated:          message.Truncation,
		RecursionDesired:   message.RecursionDesired,
		RecursionAvailable: message.RecursionAvailable,
		Zero:               message.Reserved&4 != 0,
		AuthenticatedData:  message.Reserved&2 != 0,
		CheckingDisabled:   message.Reserved&1 != 0,
	}
	if err := wire.Pack(); err != nil {
		return nil, fmt.Errorf("pack DNS header: %w", err)
	}
	for i, count := range []int{len(message.Questions), len(message.Answers), len(message.Authorities), len(message.Additionals)} {
		binary.BigEndian.PutUint16(wire.Data[4+i*2:], uint16(count))
	}
	return wire.Data, nil
}
