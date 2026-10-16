// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v4"
	"google.golang.org/protobuf/encoding/protowire"
)

type numberRepresentation struct {
	kind  string
	value string
}

func protobufNumber(field wireField) (*yaml.Node, error) {
	var reprs []numberRepresentation
	var tag string
	switch field.typ {
	case protowire.VarintType:
		reprs = append(reprs, numberRepresentation{"u64", strconv.FormatUint(field.bits, 10)})
		if field.bits>>63 != 0 {
			reprs = append(reprs, numberRepresentation{"i64", strconv.FormatInt(int64(field.bits), 10)})
		} else {
			reprs = append(reprs, numberRepresentation{"!sint", strconv.FormatInt(protowire.DecodeZigZag(field.bits), 10)})
		}
	case protowire.Fixed32Type:
		tag = "!fixed32"
		bits := uint32(field.bits)
		reprs = append(reprs, numberRepresentation{"u32", strconv.FormatUint(uint64(bits), 10)})
		f := math.Float32frombits(bits)
		if !math.IsNaN(float64(f)) && math.Abs(float64(f)) > 0.0000001 {
			reprs = append(reprs, numberRepresentation{"f32", protobufFloat(float64(f), 32)})
		}
		if bits>>31 != 0 {
			reprs = append(reprs, numberRepresentation{"i32", strconv.FormatInt(int64(int32(bits)), 10)})
		}
	case protowire.Fixed64Type:
		tag = "!fixed64"
		reprs = append(reprs, numberRepresentation{"u64", strconv.FormatUint(field.bits, 10)})
		f := math.Float64frombits(field.bits)
		if !math.IsNaN(f) && math.Abs(f) > 0.0000001 {
			reprs = append(reprs, numberRepresentation{"f64", protobufFloat(f, 64)})
		}
		if field.bits>>63 != 0 {
			reprs = append(reprs, numberRepresentation{"i64", strconv.FormatInt(int64(field.bits), 10)})
		}
	default:
		return nil, fmt.Errorf("protobuf field is not numeric")
	}
	best := 0
	for i := 1; i < len(reprs); i++ {
		candidate, current := reprs[i], reprs[best]
		if len(candidate.kind) < len(current.kind) || len(candidate.kind) == len(current.kind) && len(candidate.value) < len(current.value) {
			best = i
		}
	}
	node := &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: reprs[best].value}
	if tag == "" {
		node.Tag = "!!int"
	} else {
		node.Style = yaml.TaggedStyle
	}
	var comment strings.Builder
	for i, repr := range reprs {
		if i == best {
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
	return node, nil
}

// Numeric annotations are rendered directly: the YAML dumper emits a single
// comment separator space, but interactive protobuf text requires two.
func protobufNumberLiteral(field wireField) (string, error) {
	node, err := protobufNumber(field)
	if err != nil {
		return "", err
	}
	text := node.Value
	if node.Style == yaml.TaggedStyle {
		text = node.Tag + " " + text
	}
	if node.LineComment != "" {
		text += "  # " + node.LineComment
	}
	return text, nil
}

func protobufFloat(value float64, bits int) string {
	// Rust's Display prints decimal notation even where Go's 'g' uses exponents.
	text := strconv.FormatFloat(value, 'f', -1, bits)
	if !strings.ContainsRune(text, '.') {
		text += ".0"
	}
	return text
}

func protobufNumberBits(node *yaml.Node) (protowire.Type, uint64, error) {
	if node.Kind != yaml.ScalarNode {
		return 0, 0, fmt.Errorf("protobuf number is not a scalar")
	}
	typ := protowire.VarintType
	switch node.Tag {
	case "!fixed32":
		typ = protowire.Fixed32Type
	case "!fixed64":
		typ = protowire.Fixed64Type
	case "!sint":
		value, err := strconv.ParseInt(node.Value, 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("!sint is not an integer")
		}
		return typ, protowire.EncodeZigZag(value), nil
	}
	if value, err := strconv.ParseUint(node.Value, 10, 64); err == nil {
		return typ, value, nil
	}
	if value, err := strconv.ParseInt(node.Value, 10, 64); err == nil {
		return typ, uint64(value), nil
	}
	bits := 64
	if typ == protowire.Fixed32Type {
		bits = 32
	}
	value, err := strconv.ParseFloat(strings.TrimSuffix(node.Value, ".0"), bits)
	if err != nil {
		return 0, 0, fmt.Errorf("protobuf value is not a number")
	}
	if typ == protowire.Fixed32Type {
		return typ, uint64(math.Float32bits(float32(value))), nil
	}
	return protowire.Fixed64Type, math.Float64bits(value), nil
}
