// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

func walkGRPC(data []byte, encoding string, budget *viewBudget, visit func([]byte) error) error {
	if len(data) > maxViewBytes {
		return &LimitError{View: "gRPC", Stage: "frame", Bound: "input bytes"}
	}
	for len(data) != 0 {
		if len(data) < 5 {
			return fmt.Errorf("invalid gRPC: not enough bytes")
		}
		flag := data[0]
		if flag > 1 {
			return fmt.Errorf("invalid gRPC: first byte is not a boolean")
		}
		length := uint64(binary.BigEndian.Uint32(data[1:5]))
		if length > uint64(len(data)-5) {
			return fmt.Errorf("invalid gRPC: not enough data")
		}
		if err := budget.reserveNodes(1, "frame"); err != nil {
			return err
		}
		payload := data[5 : 5+int(length)]
		if flag != 0 {
			var err error
			payload, err = expandGRPC(payload, encoding, budget)
			if err != nil {
				return err
			}
		} else if err := budget.reserveExpanded(len(payload)); err != nil {
			return err
		}
		if err := visit(payload); err != nil {
			return err
		}
		data = data[5+int(length):]
	}
	return nil
}

func expandGRPC(data []byte, encoding string, budget *viewBudget) ([]byte, error) {
	if encoding == "identity" {
		if err := budget.reserveExpanded(len(data)); err != nil {
			return nil, err
		}
		return data, nil
	}
	var decoder io.ReadCloser
	switch encoding {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("invalid gRPC gzip: %w", err)
		}
		// The upstream single-member decoder does not decode concatenated gzip.
		reader.Multistream(false)
		decoder = reader
	case "deflate":
		decoder = flate.NewReader(bytes.NewReader(data))
	default:
		return nil, fmt.Errorf("unsupported gRPC compression")
	}
	writer := grpcExpansionWriter{budget: budget}
	_, copyErr := io.Copy(&writer, decoder)
	if err := errors.Join(copyErr, decoder.Close()); err != nil {
		return nil, fmt.Errorf("invalid gRPC compressed data: %w", err)
	}
	return writer.buffer.Bytes(), nil
}

type grpcExpansionWriter struct {
	budget *viewBudget
	buffer bytes.Buffer
}

func (w *grpcExpansionWriter) Write(data []byte) (int, error) {
	if err := w.budget.reserveExpanded(len(data)); err != nil {
		return 0, err
	}
	return w.buffer.Write(data)
}

func (b *viewBudget) reserveExpanded(count int) error {
	if count > maxViewBytes-b.expanded {
		return &LimitError{View: "gRPC", Stage: "decompress", Bound: "expanded bytes"}
	}
	b.expanded += count
	return nil
}

func appendGRPCFrame(dst, payload []byte, budget *viewBudget) ([]byte, error) {
	if len(payload) > maxViewBytes-5 {
		return nil, &LimitError{View: "gRPC", Stage: "frame", Bound: "output bytes"}
	}
	if err := budget.reserveNodes(1, "frame"); err != nil {
		return nil, err
	}
	if err := budget.reserveBytes(5+len(payload), "frame"); err != nil {
		return nil, err
	}
	dst = append(dst, 0)
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(payload)))
	return append(dst, payload...), nil
}
