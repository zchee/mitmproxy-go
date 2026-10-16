// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"cmp"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"strconv"

	yaml "go.yaml.in/yaml/v4"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

func protobufSchemaNodes(data []byte, descriptor protoreflect.MessageDescriptor, budget *viewBudget) (*yaml.Node, error) {
	if err := preflightSchema(data, descriptor, budget, 0); err != nil {
		return nil, err
	}
	if err := budget.reserveNodes(1, "dynamic protobuf message"); err != nil {
		return nil, err
	}
	message := dynamicpb.NewMessage(descriptor)
	if err := (proto.UnmarshalOptions{RecursionLimit: maxViewDepth}).Unmarshal(data, message); err != nil {
		return nil, fmt.Errorf("protobuf descriptor does not match wire data")
	}
	return protobufMessageNode(message, budget, 0)
}

func preflightSchema(data []byte, descriptor protoreflect.MessageDescriptor, budget *viewBudget, depth int) error {
	fields, err := parseWire(data, budget, depth)
	if err != nil {
		return err
	}
	for _, wire := range fields {
		field := descriptor.Fields().ByNumber(wire.number)
		if field == nil {
			continue
		}
		expected := protobufKindWire(field.Kind())
		if wire.typ == protowire.BytesType && field.IsList() && expected != protowire.BytesType {
			packed := wire.data
			for len(packed) != 0 {
				if err := budget.reserveNodes(1, "packed field"); err != nil {
					return err
				}
				var n int
				switch expected {
				case protowire.Fixed32Type:
					_, n = protowire.ConsumeFixed32(packed)
				case protowire.Fixed64Type:
					_, n = protowire.ConsumeFixed64(packed)
				default:
					_, n = protowire.ConsumeVarint(packed)
				}
				if n < 0 {
					return fmt.Errorf("invalid packed protobuf field")
				}
				packed = packed[n:]
			}
			continue
		}
		if wire.typ != expected {
			return fmt.Errorf("protobuf descriptor does not match wire type")
		}
		if field.Message() != nil {
			if err := preflightSchema(wire.data, field.Message(), budget, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func protobufKindWire(kind protoreflect.Kind) protowire.Type {
	switch kind {
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return protowire.Fixed32Type
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return protowire.Fixed64Type
	case protoreflect.StringKind, protoreflect.BytesKind, protoreflect.MessageKind:
		return protowire.BytesType
	default:
		return protowire.VarintType
	}
}

func protobufMessageNode(message protoreflect.Message, budget *viewBudget, depth int) (*yaml.Node, error) {
	if err := budget.checkDepth(depth, "schema YAML"); err != nil {
		return nil, err
	}
	if err := budget.reserveNodes(1, "schema YAML"); err != nil {
		return nil, err
	}
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	fields := message.Descriptor().Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		if !message.Has(field) {
			continue
		}
		if err := budget.reserveNodes(1, "schema key"); err != nil {
			return nil, err
		}
		value, err := protobufKnownNode(field, message.Get(field), budget, depth)
		if err != nil {
			return nil, err
		}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: string(field.Name())}, value)
	}
	unknown, err := protobufNodes(message.GetUnknown(), budget, depth)
	if err != nil {
		return nil, err
	}
	root.Content = append(root.Content, unknown.Content...)
	return root, nil
}

func protobufKnownNode(field protoreflect.FieldDescriptor, value protoreflect.Value, budget *viewBudget, depth int) (*yaml.Node, error) {
	if err := budget.checkDepth(depth+1, "schema value"); err != nil {
		return nil, err
	}
	if field.IsList() {
		list := value.List()
		if err := budget.reserveNodes(1, "schema sequence"); err != nil {
			return nil, err
		}
		node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for i := range list.Len() {
			child, err := protobufKnownScalar(field, list.Get(i), budget, depth+1)
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content, child)
		}
		return node, nil
	}
	if field.IsMap() {
		mapping := value.Map()
		if err := budget.reserveNodes(1+mapping.Len(), "schema map"); err != nil {
			return nil, err
		}
		keys := make([]protoreflect.MapKey, 0, mapping.Len())
		mapping.Range(func(key protoreflect.MapKey, _ protoreflect.Value) bool {
			keys = append(keys, key)
			return true
		})
		slices.SortFunc(keys, func(a, b protoreflect.MapKey) int {
			switch field.MapKey().Kind() {
			case protoreflect.BoolKind:
				if a.Bool() == b.Bool() {
					return 0
				}
				if !a.Bool() {
					return -1
				}
				return 1
			case protoreflect.StringKind:
				return cmp.Compare(a.String(), b.String())
			case protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.Fixed32Kind, protoreflect.Fixed64Kind:
				return cmp.Compare(a.Uint(), b.Uint())
			default:
				return cmp.Compare(a.Int(), b.Int())
			}
		})
		node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for _, key := range keys {
			keyNode, err := protobufKnownScalar(field.MapKey(), key.Value(), budget, depth+1)
			if err != nil {
				return nil, err
			}
			valueNode, err := protobufKnownScalar(field.MapValue(), mapping.Get(key), budget, depth+1)
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content, keyNode, valueNode)
		}
		return node, nil
	}
	return protobufKnownScalar(field, value, budget, depth)
}

func protobufKnownScalar(field protoreflect.FieldDescriptor, value protoreflect.Value, budget *viewBudget, depth int) (*yaml.Node, error) {
	if field.Kind() == protoreflect.MessageKind {
		return protobufMessageNode(value.Message(), budget, depth+1)
	}
	if err := budget.reserveNodes(1, "schema scalar"); err != nil {
		return nil, err
	}
	node := &yaml.Node{Kind: yaml.ScalarNode}
	switch field.Kind() {
	case protoreflect.BoolKind:
		node.Tag, node.Value = "!!bool", strconv.FormatBool(value.Bool())
	case protoreflect.StringKind:
		if err := budget.reserveScalar(len(value.String())); err != nil {
			return nil, err
		}
		node.Tag, node.Value = "!!str", value.String()
	case protoreflect.BytesKind:
		if len(value.Bytes()) > maxViewBytes/2 {
			return nil, &LimitError{View: budget.view, Stage: "schema binary", Bound: "output bytes"}
		}
		if err := budget.reserveScalar(2 * len(value.Bytes())); err != nil {
			return nil, err
		}
		node.Tag, node.Value, node.Style = "!binary", hex.EncodeToString(value.Bytes()), yaml.TaggedStyle
	case protoreflect.EnumKind:
		if enum := field.Enum().Values().ByNumber(value.Enum()); enum != nil {
			node.Tag, node.Value = "!!str", string(enum.Name())
		} else {
			node.Tag, node.Value = "!!int", strconv.FormatInt(int64(value.Enum()), 10)
		}
	case protoreflect.Int32Kind, protoreflect.Int64Kind, protoreflect.Sint32Kind, protoreflect.Sint64Kind, protoreflect.Sfixed32Kind, protoreflect.Sfixed64Kind:
		node.Tag, node.Value = "!!int", strconv.FormatInt(value.Int(), 10)
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.Fixed32Kind, protoreflect.Fixed64Kind:
		node.Tag, node.Value = "!!int", strconv.FormatUint(value.Uint(), 10)
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		node.Tag = "!!float"
		switch f := value.Float(); {
		case math.IsNaN(f):
			node.Value = ".nan"
		case math.IsInf(f, 1):
			node.Value = ".inf"
		case math.IsInf(f, -1):
			node.Value = "-.inf"
		default:
			bits := 64
			if field.Kind() == protoreflect.FloatKind {
				bits = 32
			}
			node.Value = protobufFloat(f, bits)
		}
	default:
		return nil, fmt.Errorf("unsupported protobuf descriptor kind")
	}
	return node, nil
}
