// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v4"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	protobufWireStage = "Protobuf wire"
	protobufYAMLStage = "Protobuf YAML"
)

var (
	errProtobufVaryingTypes = errors.New("varying types in protobuf")
	errProtobufEndGroup     = errors.New("unexpected protobuf end group")
)

// protobufWireField keeps integer bits intact and borrows length-delimited
// bytes from the input.
type protobufWireField struct {
	number protowire.Number
	typ    protowire.Type
	bits   uint64
	data   []byte
}

// parseProtobufWire reads one message level. Fields are returned grouped by
// number in ascending order, keeping the occurrence order within a number.
// Groups are skipped, as the Rust view's runtime discards them.
func parseProtobufWire(data []byte, budget *viewBudget, depth int) ([]protobufWireField, error) {
	if err := budget.checkInput(protobufWireStage, uint64(len(data))); err != nil {
		return nil, err
	}
	if err := budget.checkDepth(protobufWireStage, depth); err != nil {
		return nil, err
	}
	width := uint64(reflect.TypeFor[protobufWireField]().Size())
	var fields []protobufWireField
	for len(data) != 0 {
		number, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, fmt.Errorf("invalid protobuf tag: %w", protowire.ParseError(n))
		}
		data = data[n:]
		if err := budget.chargeNodes(protobufWireStage, 1); err != nil {
			return nil, err
		}
		field := protobufWireField{number: number, typ: typ}
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
		case protowire.StartGroupType:
			skipped, err := skipProtobufGroup(data, budget, depth+1)
			if err != nil {
				return nil, err
			}
			data = data[skipped:]
			continue
		case protowire.EndGroupType:
			return nil, errProtobufEndGroup
		default:
			return nil, errors.New("invalid protobuf wire type")
		}
		if n < 0 {
			return nil, fmt.Errorf("invalid protobuf value: %w", protowire.ParseError(n))
		}
		if err := budget.chargeMaterialization(protobufWireStage, width); err != nil {
			return nil, err
		}
		fields = append(fields, field)
		data = data[n:]
	}
	slices.SortStableFunc(fields, func(a, b protobufWireField) int { return int(a.number) - int(b.number) })
	return fields, nil
}

// skipProtobufGroup consumes a group body. Its end tag need not repeat the
// opening field number, matching the pinned runtime; the traversal still
// spends work for every tag it reads.
func skipProtobufGroup(data []byte, budget *viewBudget, depth int) (int, error) {
	if err := budget.checkDepth(protobufWireStage, depth); err != nil {
		return 0, err
	}
	remaining := data
	open := 1
	for len(remaining) != 0 {
		number, typ, n := protowire.ConsumeTag(remaining)
		if n < 0 {
			return 0, fmt.Errorf("invalid protobuf group tag: %w", protowire.ParseError(n))
		}
		if err := budget.chargeNodes(protobufWireStage, 1); err != nil {
			return 0, err
		}
		remaining = remaining[n:]
		switch typ {
		case protowire.StartGroupType:
			open++
			if err := budget.checkDepth(protobufWireStage, depth+open-1); err != nil {
				return 0, err
			}
		case protowire.EndGroupType:
			open--
			if open == 0 {
				return len(data) - len(remaining), nil
			}
		default:
			n = protowire.ConsumeFieldValue(number, typ, remaining)
			if n < 0 {
				return 0, fmt.Errorf("invalid protobuf group value: %w", protowire.ParseError(n))
			}
			remaining = remaining[n:]
		}
	}
	return 0, errors.New("unterminated protobuf group")
}

// protobufUnknownNode renders a message with no known fields: numeric keys in
// ascending order, repeated numbers as sequences.
func protobufUnknownNode(data []byte, budget *viewBudget, depth int) (*yaml.Node, error) {
	fields, err := parseProtobufWire(data, budget, depth)
	if err != nil {
		return nil, err
	}
	node := &yaml.Node{Kind: yaml.MappingNode}
	if err := appendProtobufUnknownFields(node, fields, budget, depth); err != nil {
		return nil, err
	}
	return node, nil
}

// appendProtobufUnknownFields appends key and value nodes for every field
// number in fields, which are grouped by number.
func appendProtobufUnknownFields(node *yaml.Node, fields []protobufWireField, budget *viewBudget, depth int) error {
	for start := 0; start < len(fields); {
		end := start + 1
		for end < len(fields) && fields[end].number == fields[start].number {
			end++
		}
		group := fields[start:end]
		valueDepth := depth
		if len(group) > 1 {
			valueDepth++
			if err := budget.checkDepth(protobufYAMLStage, valueDepth); err != nil {
				return err
			}
		}
		values, err := protobufUnknownValues(group, budget, valueDepth)
		if err != nil {
			return err
		}
		if err := budget.chargeNodes(protobufYAMLStage, 2); err != nil {
			return err
		}
		key := &yaml.Node{Kind: yaml.ScalarNode, Value: strconv.Itoa(int(group[0].number))}
		value := values[0]
		if len(group) > 1 {
			value = &yaml.Node{Kind: yaml.SequenceNode, Content: values}
		}
		node.Content = append(node.Content, key, value)
		start = end
	}
	return nil
}

// protobufUnknownValues infers one type for every occurrence of a field
// number, as the Rust view does: a fixed32 occurrence makes the field fixed32,
// else fixed64, else varint; only all-length-delimited fields are read as
// strings, nested messages or binary.
func protobufUnknownValues(fields []protobufWireField, budget *viewBudget, depth int) ([]*yaml.Node, error) {
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
	if err := budget.chargeMaterialization(protobufYAMLStage, uint64(len(fields))*uint64(reflect.TypeFor[*yaml.Node]().Size())); err != nil {
		return nil, err
	}
	values := make([]*yaml.Node, len(fields))
	if protobufReadable(fields) {
		for i, field := range fields {
			node, err := protobufStringNode(string(field.data), budget)
			if err != nil {
				return nil, err
			}
			values[i] = node
		}
		return values, nil
	}
	// The first occurrence defines the nested shape for later occurrences.
	// A failed guess still spends this rendering's budget.
	first, err := protobufUnknownNode(fields[0].data, budget, depth+1)
	if _, limited := errors.AsType[*LimitError](err); limited {
		return nil, err
	}
	if err == nil {
		values[0] = first
		nested := true
		for i, field := range fields[1:] {
			parsed, err := parseProtobufWire(field.data, budget, depth+1)
			if err != nil {
				if _, limited := errors.AsType[*LimitError](err); limited {
					return nil, err
				}
				nested = false
				break
			}
			values[i+1], err = protobufShapedNode(parsed, first, budget, depth+1)
			if err != nil {
				return nil, err
			}
		}
		if nested {
			return values, nil
		}
	}
	for i, field := range fields {
		node, err := protobufBinaryNode(field.data, budget)
		if err != nil {
			return nil, err
		}
		values[i] = node
	}
	return values, nil
}

// protobufReadable reports UTF-8 text made only of printable ASCII and ASCII
// whitespace in every occurrence.
func protobufReadable(fields []protobufWireField) bool {
	for _, field := range fields {
		for _, b := range field.data {
			if (b < 0x20 || b > 0x7e) && b != '\t' && b != '\n' && b != '\r' && b != '\f' && b != ' ' {
				return false
			}
		}
	}
	return true
}

func protobufStringNode(text string, budget *viewBudget) (*yaml.Node, error) {
	if err := budget.chargeNodes(protobufYAMLStage, 1); err != nil {
		return nil, err
	}
	if err := budget.chargeMaterialization(protobufYAMLStage, uint64(len(text))); err != nil {
		return nil, err
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Value: text, Style: yamlStringStyle(text)}, nil
}

// protobufBinaryNode renders bytes as lowercase hexadecimal under !binary.
func protobufBinaryNode(data []byte, budget *viewBudget) (*yaml.Node, error) {
	if err := budget.chargeNodes(protobufYAMLStage, 1); err != nil {
		return nil, err
	}
	if uint64(len(data)) > math.MaxUint64/2 {
		return nil, budget.refusal(protobufYAMLStage, "materialized bytes", 0, math.MaxUint64, budget.limits.OutputBytes)
	}
	if err := budget.chargeMaterialization(protobufYAMLStage, 2*uint64(len(data))); err != nil {
		return nil, err
	}
	text := hex.EncodeToString(data)
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!binary", Value: text, Style: yamlStringStyle(text)}, nil
}

// protobufNumericNodes renders fields of one numeric wire type. In a repeated
// field, length-delimited occurrences are packed values of that type.
func protobufNumericNodes(fields []protobufWireField, typ protowire.Type, repeated bool, budget *viewBudget) ([]*yaml.Node, error) {
	var values []*yaml.Node
	appendNumber := func(bits uint64) error {
		if err := budget.chargeNodes(protobufYAMLStage, 1); err != nil {
			return err
		}
		if err := budget.chargeMaterialization(protobufYAMLStage, uint64(reflect.TypeFor[*yaml.Node]().Size())); err != nil {
			return err
		}
		values = append(values, protobufNumberNode(typ, bits))
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
			return nil, errProtobufVaryingTypes
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

// protobufShapedNode renders a later occurrence of a nested field with the
// shape inferred from the first one: fields the shape lacks are omitted and
// a field whose wire type differs from the shape fails.
func protobufShapedNode(fields []protobufWireField, shape *yaml.Node, budget *viewBudget, depth int) (*yaml.Node, error) {
	if err := budget.checkDepth(protobufYAMLStage, depth); err != nil {
		return nil, err
	}
	if err := budget.chargeNodes(protobufYAMLStage, 1); err != nil {
		return nil, err
	}
	root := &yaml.Node{Kind: yaml.MappingNode}
	position := 0
	for i := 0; i < len(shape.Content); i += 2 {
		key, sample := shape.Content[i], shape.Content[i+1]
		number, err := strconv.Atoi(key.Value)
		if err != nil {
			return nil, errors.New("invalid inferred protobuf field")
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
			if err := budget.checkDepth(protobufYAMLStage, valueDepth); err != nil {
				return nil, err
			}
		} else {
			group = group[len(group)-1:]
		}
		values, err := protobufShapedValues(group, sample, repeated, budget, valueDepth)
		if err != nil {
			return nil, err
		}
		if len(values) == 0 {
			continue
		}
		if err := budget.chargeNodes(protobufYAMLStage, 2); err != nil {
			return nil, err
		}
		value := values[0]
		if repeated {
			value = &yaml.Node{Kind: yaml.SequenceNode, Content: values}
		}
		keyCopy := *key
		root.Content = append(root.Content, &keyCopy, value)
	}
	return root, nil
}

func protobufShapedValues(group []protobufWireField, sample *yaml.Node, repeated bool, budget *viewBudget, depth int) ([]*yaml.Node, error) {
	if typ, numeric := protobufSampleType(sample); numeric {
		return protobufNumericNodes(group, typ, repeated, budget)
	}
	var values []*yaml.Node
	for _, field := range group {
		if field.typ != protowire.BytesType {
			return nil, errProtobufVaryingTypes
		}
		var value *yaml.Node
		var err error
		switch {
		case sample.Kind == yaml.MappingNode:
			var parsed []protobufWireField
			parsed, err = parseProtobufWire(field.data, budget, depth+1)
			if err == nil {
				value, err = protobufShapedNode(parsed, sample, budget, depth+1)
			}
		case sample.Tag == "!binary":
			value, err = protobufBinaryNode(field.data, budget)
		default:
			if !protobufReadable([]protobufWireField{field}) {
				return nil, errors.New("invalid nested protobuf string")
			}
			value, err = protobufStringNode(string(field.data), budget)
		}
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

// protobufSampleType reports the numeric wire type a rendered sample stands
// for: a fixed tag, or an untagged integer from a varint.
func protobufSampleType(sample *yaml.Node) (protowire.Type, bool) {
	switch {
	case sample.Kind != yaml.ScalarNode:
		return 0, false
	case sample.Tag == "!fixed32":
		return protowire.Fixed32Type, true
	case sample.Tag == "!fixed64":
		return protowire.Fixed64Type, true
	case sample.Tag == "" && sample.Style == 0 && yamlCoreScalarKind(sample.Value) == yamlCoreInt:
		return protowire.VarintType, true
	}
	return 0, false
}

// protobufNumberNode shows the shortest of a number's interpretations as the
// value and the others as an inline comment, as the Rust view does: varints
// as u64 with an i64 or zigzag alternative, fixed widths as unsigned with a
// float and signed alternative.
func protobufNumberNode(typ protowire.Type, bits uint64) *yaml.Node {
	type representation struct{ kind, value string }
	var reprs []representation
	node := &yaml.Node{Kind: yaml.ScalarNode}
	switch typ {
	case protowire.Fixed32Type:
		node.Tag = "!fixed32"
		value := uint32(bits)
		reprs = append(reprs, representation{"u32", strconv.FormatUint(uint64(value), 10)})
		if f := math.Float32frombits(value); !math.IsNaN(float64(f)) && math.Abs(float64(f)) > 0.0000001 {
			reprs = append(reprs, representation{"f32", protobufFloatDisplay(float64(f), 32)})
		}
		if value>>31 != 0 {
			reprs = append(reprs, representation{"i32", strconv.FormatInt(int64(int32(value)), 10)})
		}
	case protowire.Fixed64Type:
		node.Tag = "!fixed64"
		reprs = append(reprs, representation{"u64", strconv.FormatUint(bits, 10)})
		if f := math.Float64frombits(bits); !math.IsNaN(f) && math.Abs(f) > 0.0000001 {
			reprs = append(reprs, representation{"f64", protobufFloatDisplay(f, 64)})
		}
		if bits>>63 != 0 {
			reprs = append(reprs, representation{"i64", strconv.FormatInt(int64(bits), 10)})
		}
	default:
		reprs = append(reprs, representation{"u64", strconv.FormatUint(bits, 10)})
		if bits>>63 != 0 {
			reprs = append(reprs, representation{"i64", strconv.FormatInt(int64(bits), 10)})
		} else {
			reprs = append(reprs, representation{"!sint", strconv.FormatInt(protowire.DecodeZigZag(bits), 10)})
		}
	}
	best := 0
	for i := 1; i < len(reprs); i++ {
		candidate, current := reprs[i], reprs[best]
		if len(candidate.kind) < len(current.kind) || len(candidate.kind) == len(current.kind) && len(candidate.value) < len(current.value) {
			best = i
		}
	}
	node.Value = reprs[best].value
	var comment strings.Builder
	for _, repr := range reprs {
		if repr.kind == reprs[best].kind {
			continue
		}
		if comment.Len() != 0 {
			comment.WriteString(", ")
		}
		comment.WriteString(repr.kind)
		comment.WriteString(": ")
		comment.WriteString(repr.value)
	}
	node.LineComment = comment.String()
	return node
}

// protobufFloatDisplay formats an alternative float in positional notation
// with the shortest digits of its width, keeping a fractional part so the
// value reads back as a float.
func protobufFloatDisplay(value float64, bits int) string {
	switch {
	case math.IsInf(value, 1):
		return "inf.0"
	case math.IsInf(value, -1):
		return "-inf.0"
	}
	text := strconv.FormatFloat(value, 'f', -1, bits)
	if !strings.ContainsRune(text, '.') {
		text += ".0"
	}
	return text
}
