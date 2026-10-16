// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package contentviewsdraft develops bounded interactive content-view codecs.
package contentviewsdraft

import (
	"fmt"
	"slices"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	maxViewBytes = 64 << 20
	maxViewDepth = 64
	maxViewNodes = 1_000_000
)

// LimitError identifies a content-view resource bound without exposing input.
type LimitError struct {
	View  string
	Stage string
	Bound string
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("%s %s: %s limit exceeded", e.View, e.Stage, e.Bound)
}

// A budget belongs to one whole rendering operation, including failed guesses.
type viewBudget struct {
	view     string
	nodes    int
	bytes    int
	expanded int
}

func (b *viewBudget) reserveNodes(count int, stage string) error {
	if count < 0 || count > maxViewNodes-b.nodes {
		return &LimitError{View: b.view, Stage: stage, Bound: "nodes"}
	}
	b.nodes += count
	return nil
}

func (b *viewBudget) reserveBytes(count int, stage string) error {
	if count < 0 || count > maxViewBytes-b.bytes {
		return &LimitError{View: b.view, Stage: stage, Bound: "bytes"}
	}
	b.bytes += count
	return nil
}

func (b *viewBudget) checkDepth(depth int, stage string) error {
	if depth > maxViewDepth {
		return &LimitError{View: b.view, Stage: stage, Bound: "depth"}
	}
	return nil
}

// wireField keeps integer bits intact and borrows length-delimited bytes.
type wireField struct {
	number protowire.Number
	typ    protowire.Type
	bits   uint64
	data   []byte
}

func parseWire(data []byte, budget *viewBudget, depth int) ([]wireField, error) {
	if len(data) > maxViewBytes {
		return nil, &LimitError{View: budget.view, Stage: "wire", Bound: "input bytes"}
	}
	if err := budget.checkDepth(depth, "wire"); err != nil {
		return nil, err
	}
	var fields []wireField
	for len(data) != 0 {
		number, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, fmt.Errorf("invalid protobuf tag: %w", protowire.ParseError(n))
		}
		if !number.IsValid() {
			return nil, fmt.Errorf("invalid protobuf field number")
		}
		data = data[n:]
		field := wireField{number: number, typ: typ}
		switch typ {
		case protowire.VarintType:
			field.bits, n = protowire.ConsumeVarint(data)
		case protowire.Fixed32Type:
			var bits uint32
			bits, n = protowire.ConsumeFixed32(data)
			field.bits = uint64(bits)
		case protowire.Fixed64Type:
			field.bits, n = protowire.ConsumeFixed64(data)
		case protowire.BytesType:
			field.data, n = protowire.ConsumeBytes(data)
		case protowire.StartGroupType, protowire.EndGroupType:
			return nil, fmt.Errorf("protobuf groups are not supported")
		default:
			return nil, fmt.Errorf("invalid protobuf wire type")
		}
		if n < 0 {
			return nil, fmt.Errorf("invalid protobuf value: %w", protowire.ParseError(n))
		}
		if err := budget.reserveNodes(1, "wire"); err != nil {
			return nil, err
		}
		fields = append(fields, field)
		data = data[n:]
	}
	// Stable sorting preserves duplicate occurrence order while grouping numbers.
	slices.SortStableFunc(fields, func(a, b wireField) int { return int(a.number - b.number) })
	return fields, nil
}

func appendWire(dst []byte, field wireField, budget *viewBudget) ([]byte, error) {
	if !field.number.IsValid() {
		return nil, fmt.Errorf("invalid protobuf field number")
	}
	size := protowire.SizeTag(field.number)
	switch field.typ {
	case protowire.VarintType:
		size += protowire.SizeVarint(field.bits)
	case protowire.Fixed32Type:
		size += 4
	case protowire.Fixed64Type:
		size += 8
	case protowire.BytesType:
		if len(field.data) > maxViewBytes {
			return nil, &LimitError{View: budget.view, Stage: "encode", Bound: "output bytes"}
		}
		size += protowire.SizeBytes(len(field.data))
	default:
		return nil, fmt.Errorf("invalid protobuf wire type")
	}
	if err := budget.reserveNodes(1, "encode"); err != nil {
		return nil, err
	}
	if err := budget.reserveBytes(size, "encode"); err != nil {
		return nil, err
	}
	dst = protowire.AppendTag(dst, field.number, field.typ)
	switch field.typ {
	case protowire.VarintType:
		dst = protowire.AppendVarint(dst, field.bits)
	case protowire.Fixed32Type:
		dst = protowire.AppendFixed32(dst, uint32(field.bits))
	case protowire.Fixed64Type:
		dst = protowire.AppendFixed64(dst, field.bits)
	case protowire.BytesType:
		dst = protowire.AppendBytes(dst, field.data)
	}
	return dst, nil
}
