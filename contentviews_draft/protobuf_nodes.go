// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

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
			if fields[end].typ != fields[start].typ {
				return nil, fmt.Errorf("varying types in protobuf")
			}
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
		if len(values) > 1 {
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
	if err := budget.reserveNodes(len(fields), "YAML values"); err != nil {
		return nil, err
	}
	values := make([]*yaml.Node, len(fields))
	if fields[0].typ != protowire.BytesType {
		for i, field := range fields {
			node, err := protobufNumber(field)
			if err != nil {
				return nil, err
			}
			values[i] = node
		}
		return values, nil
	}
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
	// Failed nested guesses still consume the same operation's work budget.
	nested := true
	for i, field := range fields {
		value, err := protobufNodes(field.data, budget, depth+1)
		if err != nil {
			if _, limited := errors.AsType[*LimitError](err); limited {
				return nil, err
			}
			nested = false
			break
		}
		values[i] = value
	}
	if nested {
		return values, nil
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

func (b *viewBudget) reserveScalar(count int) error {
	if count < 0 || count > maxViewBytes-b.scalars {
		return &LimitError{View: b.view, Stage: "scalar", Bound: "output bytes"}
	}
	b.scalars += count
	return nil
}
