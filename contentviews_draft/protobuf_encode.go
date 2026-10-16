// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v4"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type protobufValue struct {
	wireField
	children []protobufValue
	size     int
}

func encodeProtobufNode(node *yaml.Node, descriptor protoreflect.MessageDescriptor, budget *viewBudget) ([]byte, error) {
	values, size, err := protobufValues(node, descriptor, budget, 0)
	if err != nil {
		return nil, err
	}
	if err := budget.reserveBytes(size, "protobuf encode"); err != nil {
		return nil, err
	}
	return appendProtobufValues(make([]byte, 0, size), values), nil
}

func protobufValues(node *yaml.Node, descriptor protoreflect.MessageDescriptor, budget *viewBudget, depth int) ([]protobufValue, int, error) {
	if node == nil {
		return nil, 0, fmt.Errorf("YAML is not a mapping") //nolint:staticcheck // Preserve the pinned error prefix.
	}
	if err := budget.checkDepth(depth, "protobuf encode"); err != nil {
		return nil, 0, err
	}
	if err := budget.reserveNodes(1, "protobuf mapping"); err != nil {
		return nil, 0, err
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		return protobufValues(node.Content[0], descriptor, budget, depth)
	}
	if node.Kind == yaml.AliasNode {
		return protobufValues(node.Alias, descriptor, budget, depth+1)
	}
	if node.Kind != yaml.MappingNode || len(node.Content)%2 != 0 {
		return nil, 0, fmt.Errorf("YAML is not a mapping") //nolint:staticcheck // Preserve the pinned error prefix.
	}
	var values []protobufValue
	size := 0
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!int" && key.Tag != "!!str" {
			return nil, 0, fmt.Errorf("invalid protobuf field key")
		}
		var field protoreflect.FieldDescriptor
		if descriptor != nil && key.Tag == "!!str" {
			field = descriptor.Fields().ByName(protoreflect.Name(key.Value))
		}
		var number protowire.Number
		if field != nil {
			number = field.Number()
		} else {
			parsed, err := parseYAMLInteger(key.Value)
			if err != nil || parsed <= 0 || parsed > int64(protowire.MaxValidNumber) {
				return nil, 0, fmt.Errorf("invalid protobuf field number")
			}
			number = protowire.Number(parsed)
			if descriptor != nil {
				field = descriptor.Fields().ByNumber(number)
			}
		}
		added, err := protobufValueFields(number, field, node.Content[i+1], budget, depth)
		if err != nil {
			return nil, 0, err
		}
		for _, value := range added {
			if value.size > maxViewBytes-size {
				return nil, 0, &LimitError{View: budget.view, Stage: "protobuf encode", Bound: "output bytes"}
			}
			size += value.size
		}
		values = append(values, added...)
	}
	return values, size, nil
}

func protobufValueFields(number protowire.Number, field protoreflect.FieldDescriptor, node *yaml.Node, budget *viewBudget, depth int) ([]protobufValue, error) {
	if node == nil {
		return nil, fmt.Errorf("invalid protobuf value")
	}
	if err := budget.checkDepth(depth, "protobuf value"); err != nil {
		return nil, err
	}
	if err := budget.reserveNodes(1, "protobuf value"); err != nil {
		return nil, err
	}
	if node.Tag == "!!null" {
		return nil, nil
	}
	if node.Kind == yaml.AliasNode {
		return protobufValueFields(number, field, node.Alias, budget, depth+1)
	}
	if node.Kind == yaml.SequenceNode {
		var result []protobufValue
		for _, child := range node.Content {
			values, err := protobufValueFields(number, field, child, budget, depth+1)
			if err != nil {
				return nil, err
			}
			result = append(result, values...)
		}
		return result, nil
	}
	if node.Tag != "" && !strings.HasPrefix(node.Tag, "!!") && node.Tag != "!binary" && node.Tag != "!fixed32" && node.Tag != "!fixed64" && node.Tag != "!sint" {
		copy := *node
		copy.Tag = "!!str"
		if node.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle) == 0 {
			switch node.Value {
			case "null", "Null", "NULL", "~", "":
				copy.Tag = "!!null"
			case "true", "True", "TRUE", "false", "False", "FALSE":
				copy.Tag = "!!bool"
			default:
				if _, _, err := protobufNumberBits(node); err == nil {
					copy.Tag = "!!float"
				}
			}
		}
		return protobufValueFields(number, field, &copy, budget, depth)
	}
	value := protobufValue{number: number}
	if node.Kind == yaml.MappingNode {
		var descriptor protoreflect.MessageDescriptor
		if field != nil {
			if field.IsMap() {
				return nil, fmt.Errorf("protobuf map editing is not supported")
			}
			descriptor = field.Message()
		}
		children, size, err := protobufValues(node, descriptor, budget, depth+1)
		if err != nil {
			return nil, err
		}
		value.typ, value.children = protowire.BytesType, children
		value.size = protowire.SizeTag(number) + protowire.SizeBytes(size)
		return []protobufValue{value}, nil
	}
	if node.Kind != yaml.ScalarNode {
		return nil, fmt.Errorf("invalid protobuf value kind")
	}
	switch node.Tag {
	case "!binary":
		if len(node.Value)%2 != 0 {
			return nil, fmt.Errorf("invalid hex string")
		}
		if err := budget.reserveScalar(len(node.Value) / 2); err != nil {
			return nil, err
		}
		data, err := hex.DecodeString(node.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid hex string")
		}
		value.typ, value.data = protowire.BytesType, data
	case "!!bool":
		parsed, err := strconv.ParseBool(node.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid protobuf boolean")
		}
		value.typ = protowire.VarintType
		if parsed {
			value.bits = 1
		}
	case "!fixed32", "!fixed64", "!sint", "!!int", "!!float":
		var err error
		value.typ, value.bits, err = protobufNumberBits(node)
		if err != nil {
			return nil, err
		}
		if field != nil && strings.HasPrefix(node.Tag, "!!") {
			switch field.Kind() {
			case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
				if value.typ == protowire.Fixed64Type {
					copy := *node
					copy.Tag = "!fixed32"
					value.typ, value.bits, err = protobufNumberBits(&copy)
				}
				value.typ = protowire.Fixed32Type
			case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
				value.typ = protowire.Fixed64Type
			}
		}
		if err != nil {
			return nil, err
		}
	default:
		if err := budget.reserveScalar(len(node.Value)); err != nil {
			return nil, err
		}
		value.typ, value.data = protowire.BytesType, []byte(node.Value)
	}
	value.size = protowire.SizeTag(number)
	switch value.typ {
	case protowire.VarintType:
		value.size += protowire.SizeVarint(value.bits)
	case protowire.Fixed32Type:
		value.size += 4
	case protowire.Fixed64Type:
		value.size += 8
	case protowire.BytesType:
		value.size += protowire.SizeBytes(len(value.data))
	}
	return []protobufValue{value}, nil
}

func appendProtobufValues(dst []byte, values []protobufValue) []byte {
	for _, value := range values {
		dst = protowire.AppendTag(dst, value.number, value.typ)
		switch value.typ {
		case protowire.VarintType:
			dst = protowire.AppendVarint(dst, value.bits)
		case protowire.Fixed32Type:
			dst = protowire.AppendFixed32(dst, uint32(value.bits))
		case protowire.Fixed64Type:
			dst = protowire.AppendFixed64(dst, value.bits)
		case protowire.BytesType:
			if value.children != nil {
				bodySize := 0
				for _, child := range value.children {
					bodySize += child.size
				}
				dst = protowire.AppendVarint(dst, uint64(bodySize))
				dst = appendProtobufValues(dst, value.children)
			} else {
				dst = protowire.AppendBytes(dst, value.data)
			}
		}
	}
	return dst
}

func parseYAMLInteger(text string) (int64, error) {
	text = strings.ReplaceAll(text, "_", "")
	if value, err := strconv.ParseInt(text, 10, 64); err == nil {
		return value, nil
	}
	return strconv.ParseInt(text, 0, 64)
}
