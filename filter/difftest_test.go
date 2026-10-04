// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package filter

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestGoldenIsCurrent re-runs testdata/parse_oracle.py against the pinned
// upstream mitmproxy and checks that it reproduces the committed
// parse_golden.json byte for byte, so TestParseMatchesUpstream compares
// against what upstream really does today. After changing the corpus,
// regenerate the golden with:
//
//	uv run --python 3.13 --script filter/testdata/parse_oracle.py \
//	    filter/testdata/parse_corpus.json > filter/testdata/parse_golden.json
func TestGoldenIsCurrent(t *testing.T) {
	uv, err := exec.LookPath("uv")
	if err != nil {
		t.Skip("uv is not installed")
	}
	cmd := exec.CommandContext(t.Context(), uv, "run", "-q", "--python", "3.13", "--script",
		filepath.Join("testdata", "parse_oracle.py"), filepath.Join("testdata", "parse_corpus.json"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	got, err := cmd.Output()
	if err != nil {
		t.Fatalf("parse_oracle.py: %v\n%s", err, stderr.Bytes())
	}
	want, err := os.ReadFile(filepath.Join("testdata", "parse_golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("testdata/parse_golden.json is stale: the pinned mitmproxy produces different records (%d bytes, committed %d); regenerate it", len(got), len(want))
	}
}
