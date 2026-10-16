// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"fmt"

	"github.com/zchee/mitmproxy-go/contentviews"
)

// MsgPack renders editable MessagePack values as YAML.
type MsgPack struct {
	codec msgpackCodec
	yaml  yamlCodec
}

// Name returns the view's selection name.
func (MsgPack) Name() string { return "MsgPack" }

// SyntaxHighlight returns the renderer's syntax name.
func (MsgPack) SyntaxHighlight() string { return "yaml" }

// RenderPriority prefers MessagePack media types.
func (MsgPack) RenderPriority(_ []byte, metadata contentviews.Metadata) float64 {
	switch metadata.ContentType {
	case "application/msgpack", "application/x-msgpack":
		return 1
	default:
		return 0
	}
}

// Prettify decodes one MessagePack value without changing its scalar types.
func (v MsgPack) Prettify(data []byte, _ contentviews.Metadata) (string, error) {
	if len(data) > maxViewBytes {
		return "", &LimitError{View: "MsgPack", Stage: "decode", Bound: "input bytes"}
	}
	if v.codec == nil || v.yaml == nil {
		return "", fmt.Errorf("MsgPack adapters are not configured")
	}
	budget := &viewBudget{view: "MsgPack"}
	node, err := v.codec.Decode(data, budget)
	if err != nil {
		return "", fmt.Errorf("Failed to deserialize MsgPack: %w", err) //nolint:staticcheck // Preserve the pinned Rust error prefix.
	}
	text, err := v.yaml.Dump(node, budget)
	if err != nil {
		return "", fmt.Errorf("Failed to convert to YAML: %w", err) //nolint:staticcheck // Preserve the pinned Rust error prefix.
	}
	return text, nil
}

// Reencode parses one YAML document and preserves its MessagePack value types.
func (v MsgPack) Reencode(text string, _ contentviews.Metadata) ([]byte, error) {
	if len(text) > maxViewBytes {
		return nil, &LimitError{View: "MsgPack", Stage: "YAML", Bound: "input bytes"}
	}
	if v.codec == nil || v.yaml == nil {
		return nil, fmt.Errorf("MsgPack adapters are not configured")
	}
	budget := &viewBudget{view: "MsgPack"}
	documents, err := v.yaml.Load(text, budget)
	if err != nil {
		return nil, fmt.Errorf("Invalid YAML: %w", err) //nolint:staticcheck // Preserve the pinned Rust error prefix.
	}
	if len(documents) != 1 {
		return nil, fmt.Errorf("Invalid YAML: expected one document") //nolint:staticcheck // Preserve the pinned Rust error prefix.
	}
	data, err := v.codec.Encode(documents[0], budget)
	if err != nil {
		return nil, fmt.Errorf("Failed to encode to MsgPack: %w", err) //nolint:staticcheck // Preserve the pinned Rust error prefix.
	}
	return data, nil
}

var _ contentviews.InteractiveView = MsgPack{}
