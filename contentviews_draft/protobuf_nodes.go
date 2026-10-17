// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"

	yaml "go.yaml.in/yaml/v4"
	"google.golang.org/protobuf/encoding/protowire"
)

func protobufNodes(data []byte, budget *viewBudget, depth int) (*yaml.Node, error) {
	fields, err := parseWire(data, budget, depth)
	if err != nil {
		return nil, err
	}
	return protobufFieldsNode(fields, budget, depth)
}

func protobufFieldsNode(fields []wireField, budget *viewBudget, depth int) (*yaml.Node, error) {
	if err := budget.reserveNodes(1, "YAML nodes"); err != nil {
		return nil, err
	}
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for start := 0; start < len(fields); {
		end := start + 1
		for end < len(fields) && fields[end].number == fields[start].number {
			end++
		}
		group := fields[start:end]
		valueDepth := depth
		if len(group) > 1 {
			valueDepth++
			if err := budget.checkDepth(valueDepth, "YAML sequence"); err != nil {
				return nil, err
			}
		}
		values, err := protobufFieldNodes(group, budget, valueDepth)
		if err != nil {
			return nil, err
		}
		if err := budget.reserveNodes(1, "YAML key"); err != nil {
			return nil, err
		}
		key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(int(group[0].number))}
		value := values[0]
		if len(group) > 1 {
			if err := budget.reserveNodes(1, "YAML sequence"); err != nil {
				return nil, err
			}
			value = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: values}
		}
		root.Content = append(root.Content, key, value)
		start = end
	}
	return root, nil
}

func protobufFieldNodes(fields []wireField, budget *viewBudget, depth int) ([]*yaml.Node, error) {
	// UnknownValues in the pinned runtime prefers fixed32, fixed64, varint,
	// then length-delimited values when inferring the field's descriptor.
	typ := protowire.BytesType
	for _, field := range fields {
		switch field.typ {
		case protowire.Fixed32Type:
			typ = protowire.Fixed32Type
		case protowire.Fixed64Type:
			if typ != protowire.Fixed32Type {
				typ = protowire.Fixed64Type
			}
		case protowire.VarintType:
			if typ == protowire.BytesType {
				typ = protowire.VarintType
			}
		}
	}
	if typ != protowire.BytesType {
		return protobufNumericNodes(fields, typ, len(fields) > 1, budget)
	}
	if err := budget.reserveNodes(len(fields), "YAML values"); err != nil {
		return nil, err
	}
	values := make([]*yaml.Node, len(fields))
	readable := true
	for _, field := range fields {
		for _, b := range field.data {
			if (b < 32 || b > 126) && b != '\t' && b != '\n' && b != '\r' && b != '\f' {
				readable = false
				break
			}
		}
	}
	if readable {
		for i, field := range fields {
			if err := budget.reserveScalar(len(field.data)); err != nil {
				return nil, err
			}
			values[i] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: string(field.data)}
		}
		return values, nil
	}
	// The first occurrence defines nested fields for every later occurrence.
	// Failed guesses still consume this operation's remaining work budget.
	first, err := protobufNodes(fields[0].data, budget, depth+1)
	nested := err == nil
	if _, limited := errors.AsType[*LimitError](err); limited {
		return nil, err
	}
	if nested {
		values[0] = first
		for i, field := range fields[1:] {
			parsed, err := parseWire(field.data, budget, depth+1)
			if err != nil {
				if _, limited := errors.AsType[*LimitError](err); limited {
					return nil, err
				}
				nested = false
				break
			}
			values[i+1], err = protobufFieldsWithShape(parsed, first, budget, depth+1)
			if err != nil {
				return nil, err
			}
		}
		if nested {
			return values, nil
		}
	}
	for i, field := range fields {
		if len(field.data) > maxViewBytes/2 {
			return nil, &LimitError{View: budget.view, Stage: "binary", Bound: "output bytes"}
		}
		if err := budget.reserveScalar(2 * len(field.data)); err != nil {
			return nil, err
		}
		values[i] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!binary", Value: hex.EncodeToString(field.data), Style: yaml.TaggedStyle}
	}
	return values, nil
}

func protobufNumericNodes(fields []wireField, typ protowire.Type, repeated bool, budget *viewBudget) ([]*yaml.Node, error) {
	var values []*yaml.Node
	appendNumber := func(bits uint64) error {
		if err := budget.reserveNodes(1, "YAML numeric value"); err != nil {
			return err
		}
		node, err := protobufNumber(wireField{typ: typ, bits: bits})
		if err != nil {
			return err
		}
		values = append(values, node)
		return nil
	}
	for _, field := range fields {
		if field.typ == typ {
			if err := appendNumber(field.bits); err != nil {
				return nil, err
			}
			continue
		}
		if field.typ != protowire.BytesType || !repeated {
			return nil, fmt.Errorf("varying types in protobuf")
		}
		for packed := field.data; len(packed) != 0; {
			var bits uint64
			var n int
			switch typ {
			case protowire.Fixed32Type:
				var value uint32
				value, n = protowire.ConsumeFixed32(packed)
				bits = uint64(value)
			case protowire.Fixed64Type:
				bits, n = protowire.ConsumeFixed64(packed)
			default:
				bits, n = protowire.ConsumeVarint(packed)
			}
			if n < 0 {
				return nil, fmt.Errorf("invalid packed protobuf value: %w", protowire.ParseError(n))
			}
			if err := appendNumber(bits); err != nil {
				return nil, err
			}
			packed = packed[n:]
		}
	}
	return values, nil
}

func protobufFieldsWithShape(fields []wireField, shape *yaml.Node, budget *viewBudget, depth int) (*yaml.Node, error) {
	if err := budget.checkDepth(depth, "nested protobuf"); err != nil {
		return nil, err
	}
	if err := budget.reserveNodes(1, "nested YAML mapping"); err != nil {
		return nil, err
	}
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	position := 0
	for i := 0; i < len(shape.Content); i += 2 {
		key, sample := shape.Content[i], shape.Content[i+1]
		number, err := strconv.Atoi(key.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid inferred protobuf field")
		}
		for position < len(fields) && fields[position].number < protowire.Number(number) {
			position++
		}
		start := position
		for position < len(fields) && fields[position].number == protowire.Number(number) {
			position++
		}
		group := fields[start:position]
		if len(group) == 0 {
			continue
		}
		repeated := sample.Kind == yaml.SequenceNode
		valueDepth := depth
		if repeated {
			sample = sample.Content[0]
			valueDepth++
			if err := budget.checkDepth(valueDepth, "nested YAML sequence"); err != nil {
				return nil, err
			}
		} else {
			group = group[len(group)-1:]
		}
		var values []*yaml.Node
		switch sample.Tag {
		case "!!int", "!fixed32", "!fixed64":
			typ := protowire.VarintType
			switch sample.Tag {
			case "!fixed32":
				typ = protowire.Fixed32Type
			case "!fixed64":
				typ = protowire.Fixed64Type
			}
			values, err = protobufNumericNodes(group, typ, repeated, budget)
		default:
			for _, field := range group {
				if field.typ != protowire.BytesType {
					return nil, fmt.Errorf("varying types in nested protobuf")
				}
				var value *yaml.Node
				if sample.Kind == yaml.MappingNode {
					var parsed []wireField
					parsed, err = parseWire(field.data, budget, valueDepth+1)
					if err == nil {
						value, err = protobufFieldsWithShape(parsed, sample, budget, valueDepth+1)
					}
				} else {
					if err = budget.reserveNodes(1, "nested YAML value"); err != nil {
						return nil, err
					}
					if sample.Tag == "!!str" {
						if !utf8.Valid(field.data) {
							return nil, fmt.Errorf("invalid nested protobuf string")
						}
						if err = budget.reserveScalar(len(field.data)); err == nil {
							value = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: string(field.data)}
						}
					} else {
						if len(field.data) > maxViewBytes/2 {
							return nil, &LimitError{View: budget.view, Stage: "binary", Bound: "output bytes"}
						}
						if err = budget.reserveScalar(2 * len(field.data)); err == nil {
							value = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!binary", Value: hex.EncodeToString(field.data), Style: yaml.TaggedStyle}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				values = append(values, value)
			}
		}
		if err != nil {
			return nil, err
		}
		if len(values) == 0 {
			continue
		}
		value := values[0]
		if repeated {
			if err := budget.reserveNodes(1, "nested YAML sequence"); err != nil {
				return nil, err
			}
			value = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: values}
		}
		if err := budget.reserveNodes(1, "nested YAML key"); err != nil {
			return nil, err
		}
		keyCopy := *key
		root.Content = append(root.Content, &keyCopy, value)
	}
	return root, nil
}

func (b *viewBudget) reserveScalar(count int) error {
	if count < 0 || count > maxViewBytes-b.scalars {
		return &LimitError{View: b.view, Stage: "scalar", Bound: "output bytes"}
	}
	b.scalars += count
	return nil
}
