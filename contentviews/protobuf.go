// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"

	yaml "go.yaml.in/yaml/v4"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/zchee/mitmproxy-go/flow"
)

// Protobuf renders protobuf messages as editable YAML. Without definitions,
// fields are keyed by number and their types are inferred from the wire
// data; with the protobuf_definitions option, the message matching the
// request path names known fields.
//
// Numeric alternatives are inline comments on the YAML nodes rather than a
// textual rewrite of the rendered YAML, so string values that resemble tags
// are never changed.
type Protobuf struct{}

var _ InteractiveView = Protobuf{}

// Name returns the view's selection name.
func (Protobuf) Name() string { return "Protobuf" }

// SyntaxHighlight returns the language of the rendered text.
func (Protobuf) SyntaxHighlight() string { return "yaml" }

// RenderPriority selects the view for protobuf media types.
func (Protobuf) RenderPriority(_ []byte, metadata Metadata) float64 {
	switch metadata.ContentType {
	case "application/x-protobuf", "application/x-protobuffer":
		return 1
	default:
		return 0
	}
}

// Prettify renders one message, retrying without definitions when the
// matched definition does not fit the wire data.
func (Protobuf) Prettify(data []byte, metadata Metadata) (string, error) {
	budget := newViewBudget("Protobuf")
	descriptor, err := protobufDescriptor(metadata, budget)
	if err != nil {
		return "", err
	}
	return prettifyProtobuf(data, descriptor, budget)
}

// Reencode encodes one YAML mapping as a protobuf message.
func (Protobuf) Reencode(prettified string, metadata Metadata) ([]byte, error) {
	budget := newViewBudget("Protobuf")
	descriptor, err := protobufDescriptor(metadata, budget)
	if err != nil {
		return nil, err
	}
	return reencodeProtobuf(prettified, descriptor, budget)
}

const protobufEmpty = "{}  # empty protobuf message"

// prettifyProtobuf spends one budget on the attempt with descriptor and on
// the schema-less retry; a resource refusal is never retried.
func prettifyProtobuf(data []byte, descriptor protoreflect.MessageDescriptor, budget *viewBudget) (string, error) {
	if descriptor != nil {
		text, err := prettifyProtobufWith(data, descriptor, budget)
		if err == nil {
			return text, nil
		}
		if _, limited := errors.AsType[*LimitError](err); limited {
			return "", err
		}
	}
	text, err := prettifyProtobufWith(data, nil, budget)
	if err != nil {
		return "", err
	}
	if descriptor != nil {
		logSink().Info("Existing protobuf definition does not match, parsing as unknown proto.")
	}
	return text, nil
}

func prettifyProtobufWith(data []byte, descriptor protoreflect.MessageDescriptor, budget *viewBudget) (string, error) {
	if len(data) == 0 {
		if err := budget.chargeOutput(protobufYAMLStage, uint64(len(protobufEmpty))); err != nil {
			return "", err
		}
		return protobufEmpty, nil
	}
	node, err := protobufMessageYAML(data, descriptor, budget)
	if err != nil {
		return "", fmt.Errorf("Error parsing protobuf: %w", err) //nolint:staticcheck // The Rust view's user-facing error.
	}
	text, err := dumpBoundedYAML(node, budget, yamlEmitOptions{InlineCommentGap: 2})
	if err != nil {
		return "", fmt.Errorf("Failed to convert to YAML: %w", err) //nolint:staticcheck // The Rust view's user-facing error.
	}
	return text, nil
}

// protobufDescriptor loads the configured definitions and selects the
// message for this rendering. Definitions without a usable message leave the
// view schema-less; definitions that do not parse are an error.
func protobufDescriptor(metadata Metadata, budget *viewBudget) (protoreflect.MessageDescriptor, error) {
	if metadata.ProtobufDefinitions == "" {
		return nil, nil
	}
	schema, err := loadProtobufSchema(context.Background(), []string{metadata.ProtobufDefinitions}, schemaLimits{}, budget)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proto file(s): %w", err)
	}
	path := ""
	if f, ok := metadata.Flow.(*flow.HTTPFlow); ok && f != nil && f.Request != nil {
		path = f.Request.Path
	} else if metadata.HTTPRequest != nil {
		path = metadata.HTTPRequest.Path
	}
	descriptor, err := schema.messageDescriptor(path, metadata.HTTPRequest == nil)
	if err != nil {
		return nil, nil //nolint:nilerr // Definitions without a message render schema-less, as upstream.
	}
	return descriptor, nil
}

// protobufMessageYAML renders data as one message. With a descriptor, known
// fields come first in declaration order and unknown fields follow by number.
func protobufMessageYAML(data []byte, descriptor protoreflect.MessageDescriptor, budget *viewBudget) (*yaml.Node, error) {
	if descriptor == nil {
		return protobufUnknownNode(data, budget, 0)
	}
	if err := preflightProtobufSchema(data, descriptor, budget, 0); err != nil {
		return nil, err
	}
	message := dynamicpb.NewMessage(descriptor)
	if err := (proto.UnmarshalOptions{RecursionLimit: budget.limits.Depth}).Unmarshal(data, message); err != nil {
		return nil, errors.New("protobuf definition does not match the wire data")
	}
	return protobufKnownMessage(message, data, true, budget, 0)
}

// preflightProtobufSchema walks the wire data against the descriptor before
// any dynamic message is allocated, spending the same budget.
func preflightProtobufSchema(data []byte, descriptor protoreflect.MessageDescriptor, budget *viewBudget, depth int) error {
	fields, err := parseProtobufFields(data, true, budget, depth)
	if err != nil {
		return err
	}
	for _, wire := range fields {
		field := descriptor.Fields().ByNumber(wire.number)
		if field == nil {
			continue
		}
		expected := protobufKindWireType(field.Kind())
		if wire.typ == protowire.BytesType && field.IsList() && expected != protowire.BytesType && expected != protowire.StartGroupType {
			for packed := wire.data; len(packed) != 0; {
				if err := budget.chargeNodes(protobufWireStage, 1); err != nil {
					return err
				}
				n := protowire.ConsumeFieldValue(wire.number, expected, packed)
				if n < 0 {
					return errors.New("invalid packed protobuf field")
				}
				packed = packed[n:]
			}
			continue
		}
		if wire.typ != expected {
			return errors.New("protobuf definition does not match the wire type")
		}
		if field.Message() != nil {
			if err := preflightProtobufSchema(wire.data, field.Message(), budget, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func protobufKindWireType(kind protoreflect.Kind) protowire.Type {
	switch kind {
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return protowire.Fixed32Type
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return protowire.Fixed64Type
	case protoreflect.GroupKind:
		return protowire.StartGroupType
	case protoreflect.StringKind, protoreflect.BytesKind, protoreflect.MessageKind:
		return protowire.BytesType
	default:
		return protowire.VarintType
	}
}

// protobufKnownMessage renders the known fields present on the wire, as the
// Rust view does, so an explicit zero is shown even where proto3 presence
// would hide it. When the wire bytes of the message are not known (a map
// value), the message's own presence is used instead.
func protobufKnownMessage(message protoreflect.Message, data []byte, haveData bool, budget *viewBudget, depth int) (*yaml.Node, error) {
	if err := budget.checkDepth(protobufYAMLStage, depth); err != nil {
		return nil, err
	}
	if err := budget.chargeNodes(protobufYAMLStage, 1); err != nil {
		return nil, err
	}
	var occurrences map[protowire.Number][][]byte
	if haveData {
		wire, err := parseProtobufFields(data, true, budget, depth)
		if err != nil {
			return nil, err
		}
		occurrences = make(map[protowire.Number][][]byte)
		for _, field := range wire {
			occurrences[field.number] = append(occurrences[field.number], field.data)
		}
	}
	root := &yaml.Node{Kind: yaml.MappingNode}
	fields := message.Descriptor().Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		wire, present := occurrences[field.Number()]
		if !haveData {
			present = message.Has(field)
		}
		if !present || (field.IsList() || field.IsMap()) && !message.Has(field) {
			continue
		}
		key, err := protobufStringNode(string(field.Name()), budget)
		if err != nil {
			return nil, err
		}
		value, err := protobufKnownValue(field, message.Get(field), wire, budget, depth)
		if err != nil {
			return nil, err
		}
		root.Content = append(root.Content, key, value)
	}
	unknown, err := parseProtobufWire(message.GetUnknown(), budget, depth)
	if err != nil {
		return nil, err
	}
	if err := appendProtobufUnknownFields(root, unknown, budget, depth); err != nil {
		return nil, err
	}
	return root, nil
}

// protobufKnownValue renders a set field: repeated fields as sequences, map
// fields as mappings in ascending key order.
//
// wire holds the field's occurrences: a repeated message element comes from
// one occurrence, and a singular message merges all of them.
func protobufKnownValue(field protoreflect.FieldDescriptor, value protoreflect.Value, wire [][]byte, budget *viewBudget, depth int) (*yaml.Node, error) {
	switch {
	case field.IsList():
		depth++
		if err := budget.checkDepth(protobufYAMLStage, depth); err != nil {
			return nil, err
		}
		if err := budget.chargeNodes(protobufYAMLStage, 1); err != nil {
			return nil, err
		}
		list := value.List()
		if err := budget.chargeMaterialization(protobufYAMLStage, uint64(list.Len())*uint64(reflect.TypeFor[*yaml.Node]().Size())); err != nil {
			return nil, err
		}
		node := &yaml.Node{Kind: yaml.SequenceNode, Content: make([]*yaml.Node, 0, list.Len())}
		elements := len(wire) == list.Len()
		for i := range list.Len() {
			var data []byte
			if elements {
				data = wire[i]
			}
			child, err := protobufKnownScalar(field, list.Get(i), data, elements, budget, depth)
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content, child)
		}
		return node, nil
	case field.IsMap():
		depth++
		if err := budget.checkDepth(protobufYAMLStage, depth); err != nil {
			return nil, err
		}
		mapping := value.Map()
		if err := budget.chargeNodes(protobufYAMLStage, 1); err != nil {
			return nil, err
		}
		if err := budget.chargeMaterialization(protobufYAMLStage, uint64(mapping.Len())*uint64(reflect.TypeFor[protoreflect.MapKey]().Size())); err != nil {
			return nil, err
		}
		keys := make([]protoreflect.MapKey, 0, mapping.Len())
		mapping.Range(func(key protoreflect.MapKey, _ protoreflect.Value) bool {
			keys = append(keys, key)
			return true
		})
		slices.SortFunc(keys, func(a, b protoreflect.MapKey) int { return compareProtobufMapKeys(field.MapKey().Kind(), a, b) })
		node := &yaml.Node{Kind: yaml.MappingNode}
		for _, key := range keys {
			keyNode, err := protobufKnownScalar(field.MapKey(), key.Value(), nil, false, budget, depth)
			if err != nil {
				return nil, err
			}
			valueNode, err := protobufKnownScalar(field.MapValue(), mapping.Get(key), nil, false, budget, depth)
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content, keyNode, valueNode)
		}
		return node, nil
	}
	var data []byte
	if field.Message() != nil && len(wire) > 1 {
		var size uint64
		for _, occurrence := range wire {
			size += uint64(len(occurrence))
		}
		if err := budget.chargeMaterialization(protobufYAMLStage, size); err != nil {
			return nil, err
		}
		data = make([]byte, 0, size)
		for _, occurrence := range wire {
			data = append(data, occurrence...)
		}
	} else if len(wire) == 1 {
		data = wire[0]
	}
	return protobufKnownScalar(field, value, data, true, budget, depth)
}

func compareProtobufMapKeys(kind protoreflect.Kind, a, b protoreflect.MapKey) int {
	switch kind {
	case protoreflect.BoolKind:
		switch {
		case a.Bool() == b.Bool():
			return 0
		case !a.Bool():
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
}

// protobufKnownScalar renders one value of a known field. Integers are
// untagged, floats use the YAML float layout of their widened value, enums
// use their name when defined and bytes use !binary hexadecimal.
func protobufKnownScalar(field protoreflect.FieldDescriptor, value protoreflect.Value, data []byte, haveData bool, budget *viewBudget, depth int) (*yaml.Node, error) {
	switch field.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return protobufKnownMessage(value.Message(), data, haveData, budget, depth+1)
	case protoreflect.StringKind:
		return protobufStringNode(value.String(), budget)
	case protoreflect.BytesKind:
		return protobufBinaryNode(value.Bytes(), budget)
	case protoreflect.EnumKind:
		if enum := field.Enum().Values().ByNumber(value.Enum()); enum != nil {
			return protobufStringNode(string(enum.Name()), budget)
		}
	}
	if err := budget.chargeNodes(protobufYAMLStage, 1); err != nil {
		return nil, err
	}
	node := &yaml.Node{Kind: yaml.ScalarNode}
	switch field.Kind() {
	case protoreflect.BoolKind:
		node.Value = strconv.FormatBool(value.Bool())
	case protoreflect.EnumKind:
		node.Value = strconv.FormatInt(int64(value.Enum()), 10)
	case protoreflect.Int32Kind, protoreflect.Int64Kind, protoreflect.Sint32Kind, protoreflect.Sint64Kind, protoreflect.Sfixed32Kind, protoreflect.Sfixed64Kind:
		node.Value = strconv.FormatInt(value.Int(), 10)
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.Fixed32Kind, protoreflect.Fixed64Kind:
		node.Value = strconv.FormatUint(value.Uint(), 10)
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		node.Value = formatYAMLFloat(value.Float())
	default:
		return nil, errors.New("unsupported protobuf field kind")
	}
	return node, nil
}
