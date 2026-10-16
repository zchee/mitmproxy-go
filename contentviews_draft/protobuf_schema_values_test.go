// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	yaml "go.yaml.in/yaml/v4"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

func scalarDescriptor(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: new("values.proto"), Syntax: new("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: new("Value"),
			Field: []*descriptorpb.FieldDescriptorProto{
				{Name: new("example"), Number: new(int32(1)), Type: descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum()},
				{Name: new("child"), Number: new(int32(2)), Type: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(), TypeName: new(".Value")},
				{Name: new("numbers"), Number: new(int32(3)), Type: descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(), Label: descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()},
			},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return file.Messages().Get(0)
}

func TestProtobufSchemaValues(t *testing.T) {
	descriptor := scalarDescriptor(t)
	tests := map[string]struct {
		data []byte
		want *yaml.Node
	}{
		"known scalar": {
			data: []byte{8, 150, 1},
			want: &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "example"},
				{Kind: yaml.ScalarNode, Tag: "!!int", Value: "150"},
			}},
		},
		"nested scalar": {
			data: []byte{18, 2, 8, 42},
			want: &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "child"},
				{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Tag: "!!str", Value: "example"},
					{Kind: yaml.ScalarNode, Tag: "!!int", Value: "42"},
				}},
			}},
		},
		"packed repeated": {
			data: []byte{26, 3, 1, 2, 3},
			want: &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "numbers"},
				{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Tag: "!!int", Value: "1"},
					{Kind: yaml.ScalarNode, Tag: "!!int", Value: "2"},
					{Kind: yaml.ScalarNode, Tag: "!!int", Value: "3"},
				}},
			}},
		},
		"unknown preserved": {
			data: []byte{32, 42},
			want: &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!int", Value: "4"},
				{Kind: yaml.ScalarNode, Tag: "!!int", Value: "42", LineComment: "!sint: 21"},
			}},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := protobufSchemaNodes(tt.data, descriptor, &viewBudget{view: "Protobuf"})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("schema YAML mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProtobufSchemaReencode(t *testing.T) {
	descriptor := scalarDescriptor(t)
	tests := map[string]struct {
		text string
		data []byte
	}{
		"known field":      {"example: 150", []byte{8, 150, 1}},
		"edited wire type": {"example: hello", []byte{10, 5, 'h', 'e', 'l', 'l', 'o'}},
		"nested":           {"child: {example: 42}", []byte{18, 2, 8, 42}},
		"repeated":         {"numbers: [1, 2]", []byte{24, 1, 24, 2}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var node yaml.Node
			if err := yaml.Unmarshal([]byte(tt.text), &node); err != nil {
				t.Fatal(err)
			}
			got, err := encodeProtobufNode(&node, descriptor, &viewBudget{view: "Protobuf"})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.data, got); diff != "" {
				t.Fatalf("schema wire mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProtobufSchemaPreflight(t *testing.T) {
	descriptor := scalarDescriptor(t)
	if node, err := protobufSchemaNodes([]byte{10, 1, 'x'}, descriptor, &viewBudget{view: "Protobuf"}); err == nil || node != nil {
		t.Fatalf("mismatched schema must fail before value conversion: %v %v", node, err)
	}
	budget := &viewBudget{view: "Protobuf", nodes: maxViewNodes - 2}
	if node, err := protobufSchemaNodes([]byte{26, 3, 1, 2, 3}, descriptor, budget); node != nil || err == nil {
		t.Fatalf("packed values bypassed budget: %v %v", node, err)
	} else if _, ok := errors.AsType[*LimitError](err); !ok {
		t.Fatalf("expected typed limit, got %v", err)
	}
}
