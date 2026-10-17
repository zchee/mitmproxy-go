// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"

	yaml "go.yaml.in/yaml/v4"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const protobufEncodeStage = "Protobuf encoding"

// yamlValueError marks a scalar the YAML loader of the Rust view rejects,
// which that view reports as invalid YAML rather than as an encoding error.
type yamlValueError struct{ err error }

func (e *yamlValueError) Error() string { return "Invalid YAML: " + e.err.Error() }

func (e *yamlValueError) Unwrap() error { return e.err }

// protobufValue is one field occurrence to encode; a nested message carries
// its children and the encoded size of all of them.
type protobufValue struct {
	number   protowire.Number
	typ      protowire.Type
	bits     uint64
	data     []byte
	children []protobufValue
	nested   bool
	size     uint64
}

// reencodeProtobuf encodes one YAML mapping. Fields are written in YAML
// order; every value is encoded from its YAML type, with the descriptor only
// naming fields and choosing fixed widths for numbers.
func reencodeProtobuf(text string, descriptor protoreflect.MessageDescriptor, budget *viewBudget) ([]byte, error) {
	if err := budget.checkInput("YAML snapshot", uint64(len(text))); err != nil {
		return nil, err
	}
	documents, err := parseBoundedYAML([]byte(text), budget)
	if err != nil {
		return nil, fmt.Errorf("Invalid YAML: %w", err) //nolint:staticcheck // The Rust view's user-facing error.
	}
	var root *yaml.Node
	switch len(documents) {
	case 0:
	case 1:
		root = documents[0]
	default:
		return nil, errors.New("Invalid YAML: more than one YAML document") //nolint:staticcheck // The Rust view's user-facing error.
	}
	values, size, err := protobufEncodeMessage(root, descriptor, budget, 0)
	if err != nil {
		return nil, err
	}
	if err := budget.checkOutput(protobufEncodeStage, size); err != nil {
		return nil, err
	}
	data := appendProtobufValues(make([]byte, 0, size), values)
	if err := budget.chargeOutput(protobufEncodeStage, uint64(len(data))); err != nil {
		return nil, err
	}
	return data, nil
}

func protobufEncodeMessage(node *yaml.Node, descriptor protoreflect.MessageDescriptor, budget *viewBudget, depth int) ([]protobufValue, uint64, error) {
	if err := budget.checkDepth(protobufEncodeStage, depth); err != nil {
		return nil, 0, err
	}
	node = protobufResolveNode(node)
	if node == nil || node.Kind != yaml.MappingNode || len(node.Content)%2 != 0 {
		return nil, 0, errors.New("YAML is not a mapping")
	}
	if _, local := yamlLocalTag(node); local {
		return nil, 0, errors.New("YAML is not a mapping")
	}
	if err := budget.chargeNodes(protobufEncodeStage, 1); err != nil {
		return nil, 0, err
	}
	keys := make([]msgpackPair, 0, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		key, err := yamlMsgpackValue(node.Content[i], budget, depth)
		if err != nil {
			return nil, 0, &yamlValueError{err}
		}
		keys = append(keys, msgpackPair{Key: key})
	}
	if err := checkMsgpackKeys(keys, budget); err != nil {
		return nil, 0, &yamlValueError{err}
	}
	var values []protobufValue
	var size uint64
	for i := 0; i < len(node.Content); i += 2 {
		number, err := protobufFieldNumber(node.Content[i], descriptor, budget)
		if err != nil {
			return nil, 0, err
		}
		var field protoreflect.FieldDescriptor
		if descriptor != nil {
			field = descriptor.Fields().ByNumber(number)
		}
		added, err := protobufEncodeField(number, field, node.Content[i+1], budget, depth)
		if err != nil {
			return nil, 0, err
		}
		for _, value := range added {
			if value.size > budget.limits.OutputBytes-min(size, budget.limits.OutputBytes) {
				return nil, 0, budget.refusal(protobufEncodeStage, "output bytes", size, value.size, budget.limits.OutputBytes)
			}
			size += value.size
		}
		values = append(values, added...)
	}
	return values, size, nil
}

func protobufResolveNode(node *yaml.Node) *yaml.Node {
	for node != nil {
		switch node.Kind {
		case yaml.DocumentNode:
			if len(node.Content) == 0 {
				return nil
			}
			node = node.Content[0]
		case yaml.AliasNode:
			node = node.Alias
		default:
			return node
		}
	}
	return nil
}

// protobufFieldNumber reads a key: a string names a known field or holds a
// decimal field number, an integer is the field number.
func protobufFieldNumber(node *yaml.Node, descriptor protoreflect.MessageDescriptor, budget *viewBudget) (protowire.Number, error) {
	node = protobufResolveNode(node)
	if node == nil || node.Kind != yaml.ScalarNode {
		return 0, errors.New("unexpected protobuf field key")
	}
	if _, local := yamlLocalTag(node); local {
		return 0, errors.New("unexpected protobuf field key")
	}
	key, err := protobufScalarValue(node, budget)
	if err != nil {
		return 0, err
	}
	var number int64
	switch scalar := key.Scalar.(type) {
	case string:
		if descriptor != nil {
			if field := descriptor.Fields().ByName(protoreflect.Name(scalar)); field != nil {
				return field.Number(), nil
			}
		}
		parsed, err := strconv.ParseInt(scalar, 10, 32)
		if err != nil {
			return 0, errors.New("unknown protobuf field key")
		}
		number = parsed
	case uint64:
		if scalar > math.MaxInt32 {
			return 0, errors.New("invalid protobuf field number")
		}
		number = int64(scalar)
	case int64:
		number = scalar
	case float64:
		return 0, errors.New("invalid protobuf field number")
	default:
		return 0, errors.New("unexpected protobuf field key")
	}
	if number < int64(protowire.MinValidNumber) || number > int64(protowire.MaxValidNumber) {
		return 0, errors.New("invalid protobuf field number")
	}
	return protowire.Number(number), nil
}

// protobufScalarValue resolves a scalar with the Rust view's YAML rules. The
// standard !!binary tag has no meaning there, so its text stays a string.
func protobufScalarValue(node *yaml.Node, budget *viewBudget) (msgpackValue, error) {
	if node.Style&yaml.TaggedStyle != 0 && node.Tag == "!!binary" {
		plain := *node
		plain.Tag, plain.Style = "!!str", node.Style&^yaml.TaggedStyle|yaml.SingleQuotedStyle
		node = &plain
	}
	value, err := yamlMsgpackScalar(node, budget)
	if err != nil {
		return msgpackValue{}, &yamlValueError{err}
	}
	return value, nil
}

func protobufEncodeField(number protowire.Number, field protoreflect.FieldDescriptor, node *yaml.Node, budget *viewBudget, depth int) ([]protobufValue, error) {
	if err := budget.chargeNodes(protobufEncodeStage, 1); err != nil {
		return nil, err
	}
	node = protobufResolveNode(node)
	if node == nil {
		return nil, nil
	}
	if tag, local := yamlLocalTag(node); local {
		inner := *node
		inner.Tag, inner.Style = "", node.Style&^yaml.TaggedStyle
		switch tag {
		case "!binary", "!fixed32", "!fixed64", "!sint":
			return protobufEncodeTagged(number, tag, &inner, budget)
		}
		// The Rust view discards any other tag and encodes the value.
		logSink().Info("Unexpected YAML tag, discarding.", "tag", tag)
		return protobufEncodeField(number, field, &inner, budget, depth)
	}
	switch node.Kind {
	case yaml.SequenceNode:
		if err := budget.checkDepth(protobufEncodeStage, depth+1); err != nil {
			return nil, err
		}
		var values []protobufValue
		for _, child := range node.Content {
			added, err := protobufEncodeField(number, field, child, budget, depth+1)
			if err != nil {
				return nil, err
			}
			values = append(values, added...)
		}
		return values, nil
	case yaml.MappingNode:
		var descriptor protoreflect.MessageDescriptor
		if field != nil {
			if field.IsMap() {
				// Upstream leaves map fields unedited; refuse rather than
				// write them as an unrelated nested message.
				return nil, errors.New("protobuf map fields cannot be edited")
			}
			if field.Cardinality() != protoreflect.Repeated && field.Message() != nil {
				descriptor = field.Message()
			}
		}
		children, size, err := protobufEncodeMessage(node, descriptor, budget, depth+1)
		if err != nil {
			return nil, err
		}
		value := protobufValue{number: number, typ: protowire.BytesType, children: children, nested: true}
		value.size = uint64(protowire.SizeTag(number)) + uint64(protowire.SizeVarint(size)) + size
		if field != nil && field.Kind() == protoreflect.GroupKind {
			// A group is framed by start and end tags instead of a length.
			value.typ = protowire.StartGroupType
			value.size = 2*uint64(protowire.SizeTag(number)) + size
		}
		return []protobufValue{value}, nil
	case yaml.ScalarNode:
	default:
		return nil, errors.New("unsupported YAML node")
	}
	scalar, err := protobufScalarValue(node, budget)
	if err != nil {
		return nil, err
	}
	value := protobufValue{number: number}
	switch v := scalar.Scalar.(type) {
	case nil:
		return nil, nil
	case bool:
		value.typ = protowire.VarintType
		if v {
			value.bits = 1
		}
	case string:
		if err := budget.chargeMaterialization(protobufEncodeStage, uint64(len(v))); err != nil {
			return nil, err
		}
		value.typ, value.data = protowire.BytesType, []byte(v)
	default:
		value.typ, value.bits = protobufNumberWire(scalar.Scalar, field)
	}
	return []protobufValue{value.sized()}, nil
}

// protobufNumberWire encodes an untagged number: a field declared with a
// fixed width or float kind takes that width, otherwise non-negative and
// negative integers are varints and floats are 64-bit.
func protobufNumberWire(number any, field protoreflect.FieldDescriptor) (protowire.Type, uint64) {
	var kind protoreflect.Kind
	if field != nil {
		kind = field.Kind()
	}
	switch kind {
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		switch v := number.(type) {
		case uint64:
			return protowire.Fixed64Type, v
		case int64:
			return protowire.Fixed64Type, uint64(v)
		case float64:
			return protowire.Fixed64Type, math.Float64bits(v)
		}
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		switch v := number.(type) {
		case uint64:
			return protowire.Fixed32Type, uint64(uint32(v))
		case int64:
			return protowire.Fixed32Type, uint64(uint32(int32(v)))
		case float64:
			return protowire.Fixed32Type, uint64(math.Float32bits(float32(v)))
		}
	}
	switch v := number.(type) {
	case uint64:
		return protowire.VarintType, v
	case int64:
		return protowire.VarintType, uint64(v)
	case float64:
		return protowire.Fixed64Type, math.Float64bits(v)
	}
	return protowire.VarintType, 0
}

// protobufEncodeTagged encodes a value under one of the view's own tags.
func protobufEncodeTagged(number protowire.Number, tag string, inner *yaml.Node, budget *viewBudget) ([]protobufValue, error) {
	var scalar any
	if inner.Kind == yaml.ScalarNode {
		value, err := protobufScalarValue(inner, budget)
		if err != nil {
			return nil, err
		}
		scalar = value.Scalar
	}
	value := protobufValue{number: number}
	switch tag {
	case "!binary":
		text, ok := scalar.(string)
		if !ok {
			return nil, errors.New("binary data is not a string")
		}
		if len(text)%2 != 0 {
			return nil, errors.New("invalid hex string")
		}
		if err := budget.chargeMaterialization(protobufEncodeStage, uint64(len(text)/2)); err != nil {
			return nil, err
		}
		data, err := hex.DecodeString(text)
		if err != nil {
			return nil, errors.New("invalid hex string")
		}
		value.typ, value.data = protowire.BytesType, data
	case "!fixed32":
		value.typ = protowire.Fixed32Type
		switch v := scalar.(type) {
		case uint64:
			value.bits = uint64(uint32(v))
		case int64:
			value.bits = uint64(uint32(v))
		case float64:
			value.bits = uint64(math.Float32bits(float32(v)))
		default:
			return nil, errors.New("!fixed32 is not a number")
		}
	case "!fixed64":
		value.typ = protowire.Fixed64Type
		switch v := scalar.(type) {
		case uint64:
			value.bits = v
		case int64:
			value.bits = uint64(v)
		case float64:
			value.bits = math.Float64bits(v)
		default:
			return nil, errors.New("!fixed64 is not a number")
		}
	case "!sint":
		value.typ = protowire.VarintType
		switch v := scalar.(type) {
		case uint64:
			if v > math.MaxInt64 {
				return nil, errors.New("!sint is not an integer")
			}
			value.bits = protowire.EncodeZigZag(int64(v))
		case int64:
			value.bits = protowire.EncodeZigZag(v)
		case float64:
			return nil, errors.New("!sint is not an integer")
		default:
			return nil, errors.New("!sint is not a number")
		}
	}
	return []protobufValue{value.sized()}, nil
}

func (v protobufValue) sized() protobufValue {
	v.size = uint64(protowire.SizeTag(v.number))
	switch v.typ {
	case protowire.VarintType:
		v.size += uint64(protowire.SizeVarint(v.bits))
	case protowire.Fixed32Type:
		v.size += 4
	case protowire.Fixed64Type:
		v.size += 8
	case protowire.BytesType:
		v.size += uint64(protowire.SizeBytes(len(v.data)))
	}
	return v
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
		case protowire.StartGroupType:
			dst = appendProtobufValues(dst, value.children)
			dst = protowire.AppendTag(dst, value.number, protowire.EndGroupType)
		case protowire.BytesType:
			if value.nested {
				var body uint64
				for _, child := range value.children {
					body += child.size
				}
				dst = protowire.AppendVarint(dst, body)
				dst = appendProtobufValues(dst, value.children)
			} else {
				dst = protowire.AppendBytes(dst, value.data)
			}
		}
	}
	return dst
}
