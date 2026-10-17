// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	yaml "go.yaml.in/yaml/v4"
)

func TestProtobufNodes(t *testing.T) {
	tests := map[string]struct {
		data []byte
		want *yaml.Node
	}{
		"empty": {want: &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}},
		"string": {
			data: []byte("\x0a\x05hello"),
			want: &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!int", Value: "1"},
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "hello"},
			}},
		},
		"binary": {
			data: []byte("\x32\x03\x01\x02\x03"),
			want: &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!int", Value: "6"},
				{Kind: yaml.ScalarNode, Tag: "!binary", Value: "010203", Style: yaml.TaggedStyle},
			}},
		},
		"nested": {
			data: []byte("\x2a\x02\x08\x2a"),
			want: &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!int", Value: "5"},
				{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Tag: "!!int", Value: "1"},
					{Kind: yaml.ScalarNode, Tag: "!!int", Value: "42", LineComment: "!sint: 21"},
				}},
			}},
		},
		"repeated": {
			data: []byte("\x08\x01\x08\x02\x08\x03"),
			want: &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!int", Value: "1"},
				{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Tag: "!!int", Value: "1", LineComment: "!sint: -1"},
					{Kind: yaml.ScalarNode, Tag: "!!int", Value: "2", LineComment: "!sint: 1"},
					{Kind: yaml.ScalarNode, Tag: "!!int", Value: "3", LineComment: "!sint: -2"},
				}},
			}},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := protobufNodes(tt.data, &viewBudget{view: "Protobuf"}, 0)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("node mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProtobufNodeLimits(t *testing.T) {
	tests := map[string]struct {
		data   []byte
		budget viewBudget
		depth  int
	}{
		"value before allocation": {[]byte{8, 1}, viewBudget{view: "Protobuf", nodes: maxViewNodes - 2}, 0},
		"string before copy":      {[]byte{10, 2, 'a', 'b'}, viewBudget{view: "Protobuf", scalars: maxViewBytes - 1}, 0},
		"hex before copy":         {[]byte{10, 1, 1}, viewBudget{view: "Protobuf", scalars: maxViewBytes - 1}, 0},
		"nested depth":            {[]byte{10, 2, 8, 1}, viewBudget{view: "Protobuf"}, maxViewDepth},
		"sequence depth":          {[]byte{8, 1, 8, 2}, viewBudget{view: "Protobuf"}, maxViewDepth},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			node, err := protobufNodes(tt.data, &tt.budget, tt.depth)
			if _, ok := errors.AsType[*LimitError](err); !ok || node != nil {
				t.Fatalf("got node=%v, error=%v; want typed limit before node return", node, err)
			}
		})
	}
}

func TestProtobufNodeMixedTypes(t *testing.T) {
	if _, err := protobufNodes([]byte{8, 1, 13, 1, 0, 0, 0}, &viewBudget{view: "Protobuf"}, 0); err == nil {
		t.Fatal("mixed wire types must not be silently coerced")
	}
}
