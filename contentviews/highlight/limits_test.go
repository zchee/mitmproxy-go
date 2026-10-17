// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package highlight

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHighlightInputLimit(t *testing.T) {
	tests := map[string]struct {
		text string
	}{
		"valid UTF-8":   {text: strings.Repeat("x", maxHighlightBytes+1)},
		"invalid UTF-8": {text: strings.Repeat("\xff", maxHighlightBytes+1)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			chunks, err := Highlight(tt.text, "yaml")
			if !errors.Is(err, ErrInputTooLarge) || chunks != nil {
				t.Fatalf("Highlight returned %d chunks and %v, want input limit", len(chunks), err)
			}
			tokens, err := tokenizeChroma(tt.text, "yaml")
			if !errors.Is(err, ErrInputTooLarge) || tokens != nil {
				t.Fatalf("tokenizeChroma returned %d tokens and %v, want input limit", len(tokens), err)
			}
		})
	}
}

func TestHighlightLexerDeadline(t *testing.T) {
	tests := map[string]struct {
		repeats int
	}{
		"1000 pairs":  {repeats: 1000},
		"2000 pairs":  {repeats: 2000},
		"4000 pairs":  {repeats: 4000},
		"8000 pairs":  {repeats: 8000},
		"16000 pairs": {repeats: 16000},
		"32000 pairs": {repeats: 32000},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			text := strings.Repeat("! ", tt.repeats)
			start := time.Now()
			chunks, err := Highlight(text, "yaml")
			elapsed := time.Since(start)
			if elapsed > 2*time.Second {
				t.Fatalf("Highlight returned after %s, want bounded deadline", elapsed)
			}
			if tt.repeats >= 4000 || err != nil {
				if !errors.Is(err, ErrTimeout) || chunks != nil {
					t.Fatalf("Highlight returned %d chunks and %v after %s, want deadline error", len(chunks), err, elapsed)
				}
			}
		})
	}
}
