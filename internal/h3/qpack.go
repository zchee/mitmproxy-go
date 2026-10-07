// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package h3 implements ordered HTTP/3 protocol events and framing.
package h3

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/quic-go/qpack"
)

// HeaderField is an unnormalized field in an ordered HTTP/3 field section.
// Duplicate names and pseudo-header order are preserved.
type HeaderField struct {
	Name  string
	Value string
}

const qpackHeaderLimit = 128 << 10

func encodeHeaders(fields []HeaderField) ([]byte, error) {
	var size int
	for _, field := range fields {
		if len(field.Name) > qpackHeaderLimit-size-32 || len(field.Value) > qpackHeaderLimit-size-32-len(field.Name) {
			return nil, errors.New("h3: field section exceeds header limit")
		}
		size += len(field.Name) + len(field.Value) + 32
	}
	// The encoder emits the field-section prefix only with its first field.
	if len(fields) == 0 {
		return []byte{0, 0}, nil
	}
	var buffer bytes.Buffer
	encoder := qpack.NewEncoder(&buffer)
	for _, field := range fields {
		if err := encoder.WriteField(qpack.HeaderField{Name: field.Name, Value: field.Value}); err != nil {
			return nil, fmt.Errorf("h3: encode QPACK field: %w", err)
		}
		if buffer.Len() > qpackHeaderLimit {
			return nil, errors.New("h3: encoded field section exceeds header limit")
		}
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("h3: finish QPACK field section: %w", err)
	}
	return buffer.Bytes(), nil
}

func decodeHeaders(block []byte) ([]HeaderField, error) {
	if len(block) > qpackHeaderLimit {
		return nil, errors.New("h3: encoded field section exceeds header limit")
	}
	decode := qpack.NewDecoder().Decode(block)
	var fields []HeaderField
	var size int
	for {
		field, err := decode()
		if errors.Is(err, io.EOF) {
			return fields, nil
		}
		if err != nil {
			return nil, fmt.Errorf("h3: decode QPACK field: %w", err)
		}
		if len(field.Name) > qpackHeaderLimit-size-32 || len(field.Value) > qpackHeaderLimit-size-32-len(field.Name) {
			return nil, errors.New("h3: field section exceeds header limit")
		}
		size += len(field.Name) + len(field.Value) + 32
		fields = append(fields, HeaderField{Name: field.Name, Value: field.Value})
	}
}
