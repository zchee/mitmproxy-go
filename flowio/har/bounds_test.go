// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package har

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadEntriesBounds(t *testing.T) {
	const document = `{"log":{"entries":[]}}`
	tests := map[string]struct {
		input   string
		limit   int64
		wantErr string
	}{
		"success: exact size":                  {input: document, limit: int64(len(document))},
		"error: one byte over size":            {input: document, limit: int64(len(document) - 1), wantErr: "exceeds 256 MiB"},
		"error: trailing whitespace over size": {input: document + " ", limit: int64(len(document)), wantErr: "exceeds 256 MiB"},
		"success: depth boundary":              {input: `{"log":{"entries":[]},"ignored":` + strings.Repeat("[", 999) + "0" + strings.Repeat("]", 999) + "}", limit: maxDocumentSize},
		"error: depth overflow":                {input: `{"log":{"entries":[]},"ignored":` + strings.Repeat("[", 1000) + "0" + strings.Repeat("]", 1000) + "}", limit: maxDocumentSize, wantErr: "nesting exceeds 1000 levels"},
		"error: trailing document":             {input: document + "{}", limit: maxDocumentSize, wantErr: "trailing JSON"},
		"error: missing entries":               {input: `{"log":{}}`, limit: maxDocumentSize, wantErr: "missing log.entries"},
		"error: null entries":                  {input: `{"log":{"entries":null}}`, limit: maxDocumentSize, wantErr: "missing log.entries"},
		"error: incomplete":                    {input: `{"log":`, limit: maxDocumentSize, wantErr: "unexpected EOF"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			entries, err := readEntries(strings.NewReader(tt.input), tt.limit)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("entry count = %d", len(entries))
			}
		})
	}
	if _, err := ReadEntries(io.MultiReader(strings.NewReader("{"), errorReader{})); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("underlying error = %v", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }
