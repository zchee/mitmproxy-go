// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package options

import (
	json "encoding/json/v2"
	"fmt"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestDifferentialDecimalDigits(t *testing.T) {
	var tests map[string]struct {
		Input string `json:"input"`
		Want  int    `json:"want"`
	}
	if err := json.Unmarshal(difftest.Python(t, `
import json
import sys
import unicodedata

cases = {}
for codepoint in range(sys.maxunicode + 1):
    char = chr(codepoint)
    if unicodedata.category(char) == 'Nd':
        value = ' -' + char + '_2 '
        cases[f'U+{codepoint:04X}'] = dict(input=value, want=int(value))
print(json.dumps(cases))
`, nil), &tests); err != nil {
		t.Fatal(err)
	}
	if len(tests) < 600 {
		t.Fatalf("reference returned only %d decimal digits", len(tests))
	}
	t.Logf("checking %d decimal digits from pinned Python", len(tests))
	for name, tt := range tests {
		t.Run(fmt.Sprintf("success: %s", name), func(t *testing.T) {
			got, ok := pyInt(tt.Input)
			if !ok {
				t.Fatalf("pyInt(%q) rejected a Python decimal integer", tt.Input)
			}
			if diff := gocmp.Diff(tt.Want, got); diff != "" {
				t.Fatalf("pyInt(%q) (-Python +Go):\n%s", tt.Input, diff)
			}
		})
	}
}
