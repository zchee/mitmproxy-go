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

func TestReadEntriesCountLimit(t *testing.T) {
	const maxEntries = 100_000
	tests := map[string]struct {
		count   int
		wantErr string
	}{
		"success: exact entry bound":  {count: maxEntries},
		"error: one entry over bound": {count: maxEntries + 1, wantErr: "HAR exceeds entry-count limit"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			input := `{"log":{"entries":[` + strings.Repeat("{},", tt.count-1) + `{}]}}`
			entries, err := ReadEntries(strings.NewReader(input))
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr || entries != nil {
					t.Fatalf("ReadEntries returned %d entries, error=%v; want nil entries and %q", len(entries), err, tt.wantErr)
				}
				return
			}
			if err != nil || len(entries) != tt.count {
				t.Fatalf("ReadEntries returned %d entries, error=%v; want %d", len(entries), err, tt.count)
			}
		})
	}
}

func TestReadEntriesCountAllocations(t *testing.T) {
	// One clone per retained entry plus decoder buffers and slice growth;
	// entries beyond the bound must not allocate individual values.
	const allocationBound = 100_200
	input := `{"log":{"entries":[` + strings.Repeat("{},", 100_000) + `{}]}}`
	var readErr error
	allocations := testing.AllocsPerRun(1, func() {
		_, readErr = ReadEntries(strings.NewReader(input))
	})
	if readErr == nil || readErr.Error() != "HAR exceeds entry-count limit" {
		t.Fatalf("error = %v; want entry-count limit", readErr)
	}
	if allocations > allocationBound {
		t.Fatalf("allocations = %.0f; want at most %d", allocations, allocationBound)
	}
	t.Logf("entry-bound allocations = %.0f (bound %d)", allocations, allocationBound)
}

func TestReadEntriesDuplicateKeys(t *testing.T) {
	tests := map[string]struct {
		input   string
		want    string
		wantErr string
	}{
		"success: last entries wins":               {input: `{"log":{"entries":[1],"entries":[2]}}`, want: "2"},
		"success: last log wins":                   {input: `{"log":{"entries":[1]},"log":{"entries":[2]}}`, want: "2"},
		"success: ignored earlier invalid entries": {input: `{"log":{"entries":0,"entries":[2]}}`, want: "2"},
		"error: final log missing entries":         {input: `{"log":{"entries":[]},"log":{}}`, wantErr: "missing log.entries"},
		"error: final null entries":                {input: `{"log":{"entries":[1],"entries":null}}`, wantErr: "missing log.entries"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			entries, err := ReadEntries(strings.NewReader(tt.input))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v; want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || len(entries) != 1 || string(entries[0]) != tt.want {
				t.Fatalf("entries = %q, error = %v; want [%s]", entries, err, tt.want)
			}
		})
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }
