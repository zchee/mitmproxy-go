// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	yaml "go.yaml.in/yaml/v4"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/zchee/mitmproxy-go/contentviews"
)

// fixtureYAML uses the real YAML library for finite literals only. It is not
// the bounded production frontend and does not certify native-event preflight.
type fixtureYAML struct {
	budgets []*viewBudget
	nodes   []*yaml.Node
}

func (f *fixtureYAML) Load(text string, budget *viewBudget) ([]*yaml.Node, error) {
	f.budgets = append(f.budgets, budget)
	loader, err := yaml.NewLoader(strings.NewReader(text), yaml.WithV4Defaults())
	if err != nil {
		return nil, err
	}
	var nodes []*yaml.Node
	for {
		var node yaml.Node
		if err := loader.Load(&node); err != nil {
			if errors.Is(err, io.EOF) {
				return nodes, nil
			}
			return nil, err
		}
		nodes = append(nodes, &node)
	}
}

func (f *fixtureYAML) Dump(node *yaml.Node, budget *viewBudget) (string, error) {
	f.budgets = append(f.budgets, budget)
	f.nodes = append(f.nodes, node)
	data, err := yaml.Dump(node, yaml.WithIndent(2), yaml.WithCompactSeqIndent())
	if err != nil {
		return "", err
	}
	if err := budget.reserveBytes(len(data), "fixture output"); err != nil {
		return "", err
	}
	return string(data), nil
}

type fixtureSchema struct {
	files  []protoreflect.FileDescriptor
	cause  error
	budget *viewBudget
}

func (f *fixtureSchema) Load(_ string, budget *viewBudget) ([]protoreflect.FileDescriptor, error) {
	f.budget = budget
	return f.files, f.cause
}

func TestProtobufViewAdapters(t *testing.T) {
	descriptor := scalarDescriptor(t)
	codec := &fixtureYAML{}
	schema := &fixtureSchema{files: []protoreflect.FileDescriptor{descriptor.ParentFile()}}
	view := Protobuf{yaml: codec, schemas: schema}
	metadata := contentviews.Metadata{ProtobufDefinitions: "fixture"}
	got, err := view.Prettify([]byte{8, 150, 1}, metadata)
	if err != nil || got != "example: 150\n" {
		t.Fatalf("known render=%q, %v", got, err)
	}
	if len(codec.budgets) != 1 || codec.budgets[0] != schema.budget {
		t.Fatal("schema and renderer did not share their budget")
	}
	encoded, err := view.Reencode("example: 150", metadata)
	if err != nil || !cmp.Equal(encoded, []byte{8, 150, 1}) {
		t.Fatalf("named reencode=%x, %v", encoded, err)
	}
	if got, err := (Protobuf{}).Prettify(nil, contentviews.Metadata{}); err != nil || got != "{}  # empty protobuf message" {
		t.Fatalf("empty render=%q, %v", got, err)
	}
	cause := errors.New("invalid definition")
	schema.cause = cause
	if _, err := view.Prettify([]byte{8, 1}, metadata); !errors.Is(err, cause) {
		t.Fatalf("definition parse cause lost: %v", err)
	}
}

func TestProtobufFallbackKeepsBudget(t *testing.T) {
	descriptor := scalarDescriptor(t)
	codec := &fixtureYAML{}
	schema := &fixtureSchema{files: []protoreflect.FileDescriptor{descriptor.ParentFile()}}
	view := Protobuf{yaml: codec, schemas: schema}
	if _, err := view.Prettify([]byte{10, 5, 'h', 'e', 'l', 'l', 'o'}, contentviews.Metadata{ProtobufDefinitions: "fixture"}); err != nil {
		t.Fatal(err)
	}
	if len(codec.nodes) != 1 || codec.nodes[0].Content[0].Value != "1" || codec.nodes[0].Content[1].Value != "hello" {
		t.Fatalf("schema mismatch did not render unknown fields: %v", codec.nodes)
	}
	if schema.budget != codec.budgets[0] || schema.budget.nodes < 5 {
		t.Fatal("fallback replaced or replenished the budget")
	}
}

func TestGRPCViewAdapters(t *testing.T) {
	codec := &fixtureYAML{}
	view := GRPC{Protobuf{yaml: codec}}
	const text = "1: 150  # !sint: 75\n\n---\n\n1: 150  # !sint: 75\n"
	want := []byte{0, 0, 0, 0, 3, 8, 150, 1, 0, 0, 0, 0, 3, 8, 150, 1}
	got, err := view.Reencode(text, contentviews.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("gRPC reencode (-want +got):\n%s", diff)
	}
	if len(codec.budgets) != 1 || codec.budgets[0].bytes != len(want) {
		t.Fatal("frame headers and payloads did not share exact output accounting")
	}
	if got, err := view.Prettify(nil, contentviews.Metadata{}); got != "" || err != nil {
		t.Fatalf("empty gRPC=%q, %v", got, err)
	}
	if got, err := view.Prettify(append(want, 0), contentviews.Metadata{}); got != "" || err == nil {
		t.Fatalf("truncated final frame leaked partial output: %q %v", got, err)
	}
}

func TestInteractiveViewPriorities(t *testing.T) {
	tests := map[string]struct {
		view     contentviews.View
		media    string
		priority float64
	}{
		"protobuf":         {Protobuf{}, "application/x-protobuf", 1},
		"protobuffer":      {Protobuf{}, "application/x-protobuffer", 1},
		"protobuf default": {Protobuf{}, "text/plain", 0},
		"grpc":             {GRPC{}, "application/grpc", 1},
		"grpc proto":       {GRPC{}, "application/grpc+proto", 1},
		"prpc":             {GRPC{}, "application/prpc", 1},
		"grpc default":     {GRPC{}, "text/plain", 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tt.view.RenderPriority(nil, contentviews.Metadata{ContentType: tt.media}); got != tt.priority {
				t.Fatalf("priority=%v, want %v", got, tt.priority)
			}
			if tt.view.SyntaxHighlight() != "yaml" {
				t.Fatal("incorrect syntax highlight")
			}
		})
	}
}
