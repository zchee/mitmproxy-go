// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build ignore

// Package highlight converts source text into syntax-tagged chunks.
package highlight

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Chunk is a consecutive span of text. An empty Tag denotes unstyled text.
type Chunk struct {
	Tag  string
	Text string
}

// Languages returns the supported languages in their display order.
func Languages() []string {
	return []string{"css", "javascript", "xml", "yaml", "none", "error"}
}

// Tags returns the public nonempty syntax tags in their display order.
func Tags() []string {
	return []string{"name", "string", "number", "boolean", "comment", "error"}
}

// Highlight returns caller-owned chunks for text in language.
// It replaces malformed UTF-8 with replacement characters and returns an error
// for an unsupported language or a lexer that does not preserve the source.
func Highlight(text, language string) ([]Chunk, error) {
	switch language {
	case "none":
		return []Chunk{{Text: lossyUTF8(text)}}, nil
	case "error":
		return []Chunk{{Tag: "error", Text: lossyUTF8(text)}}, nil
	case "css", "javascript", "xml", "yaml":
		return highlightSyntax(lossyUTF8(text), language)
	default:
		return nil, fmt.Errorf("Unsupported language: %s", language)
	}
}

func coalesce(chunks []Chunk) []Chunk {
	result := chunks[:0]
	var text strings.Builder
	var tag string
	for _, chunk := range chunks {
		if chunk.Text == "" {
			continue
		}
		if text.Len() > 0 && tag != chunk.Tag && strings.Trim(chunk.Text, " \t\n\r\v\f") != "" {
			result = append(result, Chunk{Tag: tag, Text: text.String()})
			text.Reset()
		}
		if text.Len() == 0 {
			tag = chunk.Tag
		}
		text.WriteString(chunk.Text)
	}
	if text.Len() > 0 {
		result = append(result, Chunk{Tag: tag, Text: text.String()})
	}
	return result
}

func lossyUTF8(text string) string {
	if utf8.ValidString(text) {
		return text
	}
	var result strings.Builder
	result.Grow(len(text))
	for len(text) > 0 {
		r, size := utf8.DecodeRuneInString(text)
		if r != utf8.RuneError || size != 1 {
			result.WriteString(text[:size])
			text = text[size:]
			continue
		}
		// Rust replaces one maximal invalid subsequence, including a valid
		// multibyte prefix whose next continuation byte is missing or invalid.
		size = 1
		first := text[0]
		want := 0
		switch {
		case first >= 0xc2 && first <= 0xdf:
			want = 2
		case first >= 0xe0 && first <= 0xef:
			want = 3
		case first >= 0xf0 && first <= 0xf4:
			want = 4
		}
		for size < want && size < len(text) {
			b := text[size]
			if b < 0x80 || b > 0xbf || size == 1 && (first == 0xe0 && b < 0xa0 || first == 0xed && b > 0x9f || first == 0xf0 && b < 0x90 || first == 0xf4 && b > 0x8f) {
				break
			}
			size++
		}
		result.WriteRune(utf8.RuneError)
		text = text[size:]
	}
	return result.String()
}
