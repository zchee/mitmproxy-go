// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/zchee/mitmproxy-go/contentviews"
)

// GRPC renders a sequence of framed protobuf messages as YAML documents.
type GRPC struct{ Protobuf }

// Name returns the view's selection name.
func (GRPC) Name() string { return "gRPC" }

// RenderPriority prefers protobuf-bearing gRPC media types.
func (GRPC) RenderPriority(_ []byte, metadata contentviews.Metadata) float64 {
	switch metadata.ContentType {
	case "application/grpc", "application/grpc+proto", "application/prpc":
		return 1
	default:
		return 0
	}
}

// Prettify renders all frames or returns an error without partial output.
func (v GRPC) Prettify(data []byte, metadata contentviews.Metadata) (string, error) {
	if len(data) > maxViewBytes {
		return "", &LimitError{View: "gRPC", Stage: "frame", Bound: "input bytes"}
	}
	budget := &viewBudget{view: "gRPC"}
	descriptor, err := v.descriptor(metadata, budget)
	if err != nil {
		return "", err
	}
	encoding := ""
	if metadata.HTTPMessage != nil {
		encoding = metadata.HTTPMessage.Headers.Get("grpc-encoding")
	}
	if descriptor != nil {
		text, err := v.prettifyFrames(data, encoding, descriptor, budget)
		if err == nil {
			return text, nil
		}
		if _, limited := errors.AsType[*LimitError](err); limited {
			return "", err
		}
	}
	text, err := v.prettifyFrames(data, encoding, nil, budget)
	if err == nil && descriptor != nil {
		slog.Info("Existing gRPC definition does not match, parsing as unknown proto.")
	}
	return text, err
}

func (v GRPC) prettifyFrames(data []byte, encoding string, descriptor protoreflect.MessageDescriptor, budget *viewBudget) (string, error) {
	var output strings.Builder
	first := true
	err := walkGRPC(data, encoding, budget, func(payload []byte) error {
		text, err := v.prettifyWithDescriptor(payload, descriptor, budget)
		if err != nil {
			return err
		}
		if !first {
			const separator = "\n---\n\n"
			if err := budget.reserveBytes(len(separator), "YAML separator"); err != nil {
				return err
			}
			output.WriteString(separator)
		}
		first = false
		output.WriteString(text)
		return nil
	})
	if err != nil {
		return "", err
	}
	return output.String(), nil
}

// Reencode emits uncompressed frames from preflighted YAML documents.
func (v GRPC) Reencode(text string, metadata contentviews.Metadata) ([]byte, error) {
	if len(text) > maxViewBytes {
		return nil, &LimitError{View: "gRPC", Stage: "YAML", Bound: "input bytes"}
	}
	if v.yaml == nil {
		return nil, fmt.Errorf("gRPC YAML adapter is not configured")
	}
	budget := &viewBudget{view: "gRPC"}
	descriptor, err := v.descriptor(metadata, budget)
	if err != nil {
		return nil, err
	}
	documents, err := v.yaml.Load(text, budget)
	if err != nil {
		return nil, fmt.Errorf("Invalid YAML: %w", err) //nolint:staticcheck // Preserve the pinned Rust error prefix.
	}
	output := make([]byte, 0)
	for _, document := range documents {
		if err := budget.reserveNodes(1, "frame"); err != nil {
			return nil, err
		}
		if err := budget.reserveBytes(5, "frame header"); err != nil {
			return nil, err
		}
		payload, err := encodeProtobufNode(document, descriptor, budget)
		if err != nil {
			return nil, err
		}
		if uint64(len(payload)) > uint64(^uint32(0)) {
			return nil, fmt.Errorf("gRPC frame length exceeds uint32")
		}
		// The node encoder already reserved payload bytes in this same budget.
		output = append(output, 0)
		output = binary.BigEndian.AppendUint32(output, uint32(len(payload)))
		output = append(output, payload...)
	}
	return output, nil
}

var _ contentviews.InteractiveView = GRPC{}
