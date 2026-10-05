// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package emoji_test

import (
	json "encoding/json/v2"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/emoji"
)

func TestDifferentialTable(t *testing.T) {
	output := difftest.Python(t, "import json\nfrom mitmproxy.utils import emoji\nprint(json.dumps(list(emoji.emoji.items())))", nil)
	var want [][2]string
	if err := json.Unmarshal(output, &want); err != nil {
		t.Fatal(err)
	}
	names := emoji.Names()
	got := make([][2]string, len(names))
	for i, name := range names {
		char, ok := emoji.Char(name)
		if !ok {
			t.Fatalf("missing marker %q", name)
		}
		got[i] = [2]string{name, char}
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("marker table (-Python +Go):\n%s", diff)
	}
}
