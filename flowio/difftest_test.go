// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowio

import (
	"bytes"
	"testing"

	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// migrateScript migrates every flow on stdin with mitmproxy's
// compat.migrate_flow and writes the migrated dictionaries.
const migrateScript = `
import io, sys
from mitmproxy.io import compat, tnetstring
src = io.BytesIO(sys.stdin.buffer.read())
out = sys.stdout.buffer
while src.tell() < len(src.getbuffer()):
    out.write(tnetstring.dumps(compat.migrate_flow(tnetstring.load(src))))
`

// TestDifferentialMigrate compares the migrated state of every fixture in
// formats 18 to 20 with mitmproxy's, as encoded bytes, so that key order
// counts as well as values.
func TestDifferentialMigrate(t *testing.T) {
	for rel := range olderFixtures {
		t.Run(rel, func(t *testing.T) {
			want := difftest.Python(t, migrateScript, testutil.Fixture(t, rel))
			var got bytes.Buffer
			for i, m := range rawFlows(t, rel) {
				if err := migrate(m); err != nil {
					t.Fatalf("flow %d: %v", i, err)
				}
				if err := tnetstring.Dump(&got, toTnetstring(m)); err != nil {
					t.Fatalf("flow %d: %v", i, err)
				}
			}
			if !bytes.Equal(want, got.Bytes()) {
				t.Errorf("migrated flows differ from mitmproxy's (Go %d bytes, Python %d bytes)", got.Len(), len(want))
			}
		})
	}
}

// rewriteScript reads every flow on stdin with mitmproxy's FlowReader and
// writes them with its FlowWriter.
const rewriteScript = `
import io, sys
from mitmproxy.io import FlowReader, FlowWriter
src = io.BytesIO(sys.stdin.buffer.read())
out = io.BytesIO()
w = FlowWriter(out)
for f in FlowReader(src).stream():
    w.add(f)
sys.stdout.buffer.write(out.getvalue())
`

// TestDifferentialWrite compares Write(Read(file)) with what mitmproxy's
// FlowWriter(FlowReader(file)) writes, for every readable fixture, and
// checks that mitmproxy reads the file mitmproxy-go wrote back into the
// same bytes.
func TestDifferentialWrite(t *testing.T) {
	for _, rel := range readableFixtures(t) {
		t.Run(rel, func(t *testing.T) {
			src := testutil.Fixture(t, rel)
			flows, err := readAll(t, src)
			if err != nil {
				t.Fatal(err)
			}
			got := writeAll(t, flows)
			want := difftest.Python(t, rewriteScript, src)
			if !bytes.Equal(want, got) {
				t.Errorf("Write(Read(file)) differs from mitmproxy's FlowWriter(FlowReader(file)) (Go %d bytes, Python %d bytes)", len(got), len(want))
			}
			if back := difftest.Python(t, rewriteScript, got); !bytes.Equal(back, got) {
				t.Errorf("mitmproxy re-wrote the file mitmproxy-go wrote differently (Go %d bytes, Python %d bytes)", len(got), len(back))
			}
		})
	}
}

// TestDifferentialMetadata checks that mitmproxy reads flow files whose
// metadata holds values only free-form state carries, as mitmproxy-go
// writes them, and writes them back unchanged.
func TestDifferentialMetadata(t *testing.T) {
	tests := map[string]struct {
		file func(t *testing.T) []byte
	}{
		"success: integers beyond int64":       {file: bigMetadataFile},
		"success: byte-string keys, not UTF-8": {file: bytesKeyMetadataFile},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			src := tt.file(t)
			if got := difftest.Python(t, rewriteScript, src); !bytes.Equal(got, src) {
				t.Errorf("mitmproxy re-wrote the file differently:\nwant %q\n got %q", src, got)
			}
		})
	}
}
