// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// GRPC renders length-prefixed gRPC messages as YAML documents, one protobuf
// message each, and encodes edited documents as uncompressed messages.
type GRPC struct{}

var _ InteractiveView = GRPC{}

// Name returns the view's selection name.
func (GRPC) Name() string { return "gRPC" }

// SyntaxHighlight returns the language of the rendered text.
func (GRPC) SyntaxHighlight() string { return "yaml" }

// RenderPriority selects the view for gRPC media types.
func (GRPC) RenderPriority(_ []byte, metadata Metadata) float64 {
	switch metadata.ContentType {
	case "application/grpc", "application/grpc+proto", "application/prpc":
		return 1
	default:
		return 0
	}
}

// Prettify renders every message or fails without partial output. When the
// matched definition does not fit, the whole body is rendered again without
// it on the same budget.
func (GRPC) Prettify(data []byte, metadata Metadata) (string, error) {
	budget := newViewBudget("gRPC")
	encoding := ""
	if metadata.HTTPMessage != nil {
		encoding = metadata.HTTPMessage.Headers.Get("grpc-encoding")
	}
	descriptor, err := protobufDescriptor(metadata, budget)
	if err != nil {
		return "", err
	}
	return prettifyGRPC(data, encoding, descriptor, budget)
}

// Reencode encodes each YAML document as one uncompressed message.
func (GRPC) Reencode(prettified string, metadata Metadata) ([]byte, error) {
	budget := newViewBudget("gRPC")
	descriptor, err := protobufDescriptor(metadata, budget)
	if err != nil {
		return nil, err
	}
	return reencodeGRPC(prettified, descriptor, budget)
}

const (
	grpcFrameStage  = "gRPC framing"
	grpcSeparator   = "\n---\n\n"
	grpcHeaderBytes = 5
)

func prettifyGRPC(data []byte, encoding string, descriptor protoreflect.MessageDescriptor, budget *viewBudget) (string, error) {
	if err := budget.checkInput(grpcFrameStage, uint64(len(data))); err != nil {
		return "", err
	}
	if descriptor != nil {
		text, err := prettifyGRPCWith(data, encoding, descriptor, budget)
		if err == nil {
			return text, nil
		}
		if _, limited := errors.AsType[*LimitError](err); limited {
			return "", err
		}
	}
	text, err := prettifyGRPCWith(data, encoding, nil, budget)
	if err != nil {
		return "", err
	}
	if descriptor != nil {
		logSink().Info("Existing gRPC definition does not match, parsing as unknown proto.")
	}
	return text, nil
}

func prettifyGRPCWith(data []byte, encoding string, descriptor protoreflect.MessageDescriptor, budget *viewBudget) (string, error) {
	var output strings.Builder
	for messages := 0; len(data) != 0; messages++ {
		var compressed bool
		switch data[0] {
		case 0:
		case 1:
			compressed = true
		default:
			return "", errors.New("invalid gRPC: first byte is not a boolean")
		}
		if len(data) < grpcHeaderBytes {
			return "", errors.New("invalid gRPC: not enough bytes")
		}
		length := uint64(binary.BigEndian.Uint32(data[1:grpcHeaderBytes]))
		if length > uint64(len(data)-grpcHeaderBytes) {
			return "", errors.New("invalid gRPC: not enough data")
		}
		if err := budget.chargeNodes(grpcFrameStage, 1); err != nil {
			return "", err
		}
		payload := data[grpcHeaderBytes : grpcHeaderBytes+int(length)]
		if compressed {
			var err error
			payload, err = expandGRPC(payload, encoding, budget)
			if err != nil {
				return "", err
			}
		}
		text, err := prettifyProtobufWith(payload, descriptor, budget)
		if err != nil {
			return "", err
		}
		if messages != 0 {
			if err := budget.chargeOutput(grpcFrameStage, uint64(len(grpcSeparator))); err != nil {
				return "", err
			}
			output.WriteString(grpcSeparator)
		}
		output.WriteString(text)
		data = data[grpcHeaderBytes+int(length):]
	}
	return output.String(), nil
}

// expandGRPC decompresses one message with the header-selected encoding.
// deflate is raw DEFLATE, gzip reads a single member, and every expanded byte
// is charged to the call's aggregate before it is buffered.
func expandGRPC(data []byte, encoding string, budget *viewBudget) ([]byte, error) {
	var decoder io.ReadCloser
	switch encoding {
	case "identity":
		return data, nil
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("invalid gRPC gzip data: %w", err)
		}
		reader.Multistream(false)
		decoder = reader
	case "deflate":
		decoder = flate.NewReader(bytes.NewReader(data))
	default:
		return nil, errors.New("unsupported gRPC compression")
	}
	writer := grpcExpansionWriter{budget: budget}
	_, err := io.Copy(&writer, decoder)
	// flate's Close returns the reader's sticky error again, so a Close
	// error is reported only when the copy itself succeeded.
	if closeErr := decoder.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		if _, limited := errors.AsType[*LimitError](err); limited {
			return nil, err
		}
		return nil, fmt.Errorf("invalid gRPC compressed data: %w", err)
	}
	return writer.buffer.Bytes(), nil
}

type grpcExpansionWriter struct {
	budget *viewBudget
	buffer bytes.Buffer
}

func (w *grpcExpansionWriter) Write(data []byte) (int, error) {
	if err := w.budget.chargeDecompressed("gRPC decompression", uint64(len(data))); err != nil {
		return 0, err
	}
	return w.buffer.Write(data)
}

// reencodeGRPC encodes every document before writing any frame, so a failing
// document leaves no partial output.
func reencodeGRPC(text string, descriptor protoreflect.MessageDescriptor, budget *viewBudget) ([]byte, error) {
	if err := budget.checkInput("YAML snapshot", uint64(len(text))); err != nil {
		return nil, err
	}
	documents, err := parseBoundedYAML([]byte(text), budget)
	if err != nil {
		return nil, fmt.Errorf("Invalid YAML: %w", err) //nolint:staticcheck // The Rust view's user-facing error.
	}
	if len(documents) == 0 {
		// The Rust view reads an empty stream as one null document.
		documents = append(documents, nil)
	}
	type frame struct {
		values []protobufValue
		size   uint64
	}
	frames := make([]frame, 0, len(documents))
	var total uint64
	for _, document := range documents {
		if err := budget.chargeNodes(grpcFrameStage, 1); err != nil {
			return nil, err
		}
		values, size, err := protobufEncodeMessage(document, descriptor, budget, 0)
		if err != nil {
			return nil, err
		}
		if size > math.MaxUint32 {
			return nil, errors.New("gRPC message length exceeds 32 bits")
		}
		total += grpcHeaderBytes + size
		if err := budget.checkOutput(grpcFrameStage, total); err != nil {
			return nil, err
		}
		frames = append(frames, frame{values, size})
	}
	output := make([]byte, 0, total)
	for _, frame := range frames {
		output = append(output, 0)
		output = binary.BigEndian.AppendUint32(output, uint32(frame.size))
		output = appendProtobufValues(output, frame.values)
	}
	if err := budget.chargeOutput(grpcFrameStage, uint64(len(output))); err != nil {
		return nil, err
	}
	return output, nil
}
