// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// HexDump renders sixteen bytes per line, with offsets and an ASCII column.
type HexDump struct{}

// Name returns the display name.
func (HexDump) Name() string { return "Hex Dump" }

// SyntaxHighlight disables syntax highlighting.
func (HexDump) SyntaxHighlight() string { return "none" }

// RenderPriority prefers binary data over the raw text view.
func (HexDump) RenderPriority(data []byte, _ Metadata) float64 {
	if isBinary(data) {
		return 0.5
	}
	return 0
}

// Prettify reproduces the grouped hexadecimal format of the Rust view.
func (HexDump) Prettify(data []byte, _ Metadata) (string, error) {
	var out strings.Builder
	const digits = "0123456789abcdef"
	for offset := 0; offset < len(data); offset += 16 {
		if offset > 0 {
			out.WriteByte('\n')
		}
		fmt.Fprintf(&out, "%04x:   ", offset)
		part := data[offset:min(offset+16, len(data))]
		var hexColumn [50]byte
		for i := range hexColumn {
			hexColumn[i] = ' '
		}
		for i, b := range part {
			index := i*3 + i/4
			hexColumn[index] = digits[b>>4]
			hexColumn[index+1] = digits[b&15]
		}
		out.Write(hexColumn[:])
		out.WriteString("   ")
		for _, b := range part {
			if b < 32 || b > 126 {
				b = '.'
			}
			out.WriteByte(b)
		}
	}
	return out.String(), nil
}

// HexStream renders contiguous lowercase hex and accepts edited hexadecimal.
type HexStream struct{}

// Name returns the display name.
func (HexStream) Name() string { return "Hex Stream" }

// SyntaxHighlight disables syntax highlighting.
func (HexStream) SyntaxHighlight() string { return "none" }

// RenderPriority prefers binary data, below the grouped hex dump view.
func (HexStream) RenderPriority(data []byte, _ Metadata) float64 {
	if isBinary(data) {
		return 0.4
	}
	return 0
}

// Prettify returns two lowercase hex characters per byte.
func (HexStream) Prettify(data []byte, _ Metadata) (string, error) {
	return hex.EncodeToString(data), nil
}

// Reencode accepts either letter case and trailing carriage returns/newlines.
// It returns an error for odd-length input or any non-hexadecimal character.
func (HexStream) Reencode(text string, _ Metadata) ([]byte, error) {
	text = strings.TrimRight(text, "\r\n")
	if len(text)%2 != 0 {
		return nil, errors.New("Invalid hex string: uneven number of characters") //nolint:staticcheck // The Rust view's user-facing error.
	}
	data, err := hex.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("Invalid hex string: %w", err) //nolint:staticcheck // The Rust view's user-facing error.
	}
	return data, nil
}

func isBinary(data []byte) bool {
	data = data[:min(len(data), 100)]
	count := 0
	for _, b := range data {
		if b < 9 || (b > 13 && b < 32) || b > 126 {
			count++
		}
	}
	return count*10 > len(data)*3
}
