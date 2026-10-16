// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flow"
)

// Schema loading is local-only, ordered and bounded by the operation budget.
type protobufSchemaLoader interface {
	Load(path string, budget *viewBudget) ([]protoreflect.FileDescriptor, error)
}

// Protobuf renders editable protobuf fields, optionally using local definitions.
type Protobuf struct {
	yaml    yamlCodec
	schemas protobufSchemaLoader
}

// Name returns the view's selection name.
func (Protobuf) Name() string { return "Protobuf" }

// SyntaxHighlight returns the renderer's syntax name.
func (Protobuf) SyntaxHighlight() string { return "yaml" }

// RenderPriority prefers protobuf media types.
func (Protobuf) RenderPriority(_ []byte, metadata contentviews.Metadata) float64 {
	switch metadata.ContentType {
	case "application/x-protobuf", "application/x-protobuffer":
		return 1
	default:
		return 0
	}
}

// Prettify renders known fields by name and unknown fields by number.
func (v Protobuf) Prettify(data []byte, metadata contentviews.Metadata) (string, error) {
	if len(data) > maxViewBytes {
		return "", &LimitError{View: "Protobuf", Stage: "wire", Bound: "input bytes"}
	}
	budget := &viewBudget{view: "Protobuf"}
	descriptor, err := v.descriptor(metadata, budget)
	if err != nil {
		return "", err
	}
	if descriptor != nil {
		text, err := v.prettifyWithDescriptor(data, descriptor, budget)
		if err == nil {
			return text, nil
		}
		if _, limited := errors.AsType[*LimitError](err); limited {
			return "", err
		}
	}
	text, err := v.prettifyWithDescriptor(data, nil, budget)
	if err == nil && descriptor != nil {
		slog.Info("Existing protobuf definition does not match, parsing as unknown proto.")
	}
	return text, err
}

// Reencode writes edited YAML fields using explicit tags and known wire types.
func (v Protobuf) Reencode(text string, metadata contentviews.Metadata) ([]byte, error) {
	if len(text) > maxViewBytes {
		return nil, &LimitError{View: "Protobuf", Stage: "YAML", Bound: "input bytes"}
	}
	if v.yaml == nil {
		return nil, fmt.Errorf("protobuf YAML adapter is not configured")
	}
	budget := &viewBudget{view: "Protobuf"}
	descriptor, err := v.descriptor(metadata, budget)
	if err != nil {
		return nil, err
	}
	documents, err := v.yaml.Load(text, budget)
	if err != nil {
		return nil, fmt.Errorf("Invalid YAML: %w", err) //nolint:staticcheck // Preserve the pinned Rust error prefix.
	}
	if len(documents) != 1 {
		return nil, fmt.Errorf("Invalid YAML: expected one document") //nolint:staticcheck // Preserve the pinned Rust error prefix.
	}
	return encodeProtobufNode(documents[0], descriptor, budget)
}

func (v Protobuf) prettifyWithDescriptor(data []byte, descriptor protoreflect.MessageDescriptor, budget *viewBudget) (string, error) {
	if len(data) == 0 {
		const empty = "{}  # empty protobuf message"
		if err := budget.reserveBytes(len(empty), "YAML output"); err != nil {
			return "", err
		}
		return empty, nil
	}
	if v.yaml == nil {
		return "", fmt.Errorf("protobuf YAML adapter is not configured")
	}
	if descriptor != nil {
		node, err := protobufSchemaNodes(data, descriptor, budget)
		if err != nil {
			return "", err
		}
		return v.yaml.Dump(node, budget)
	}
	node, err := protobufNodes(data, budget, 0)
	if err != nil {
		return "", err
	}
	return v.yaml.Dump(node, budget)
}

func (v Protobuf) descriptor(metadata contentviews.Metadata, budget *viewBudget) (protoreflect.MessageDescriptor, error) {
	if metadata.ProtobufDefinitions == "" {
		return nil, nil
	}
	if v.schemas == nil {
		return nil, fmt.Errorf("protobuf schema adapter is not configured")
	}
	files, err := v.schemas.Load(metadata.ProtobufDefinitions, budget)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proto files: %w", err)
	}
	path := ""
	request := metadata.HTTPRequest != nil
	if f, ok := metadata.Flow.(*flow.HTTPFlow); ok && f != nil && f.Request != nil {
		path = f.Request.Path
		request = metadata.HTTPMessage == &f.Request.Message || metadata.HTTPRequest == f.Request
	} else if metadata.HTTPRequest != nil {
		path = metadata.HTTPRequest.Path
	}
	return selectProtobufMessage(files, path, request), nil
}

var _ contentviews.InteractiveView = Protobuf{}
