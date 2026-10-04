// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package flowio

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// pinnedMitmproxy is the upstream revision flowio is checked against.
const pinnedMitmproxy = "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@3368a0a"

// runPython runs script with the pinned mitmproxy, feeding it stdin, and
// returns its standard output.
func runPython(t *testing.T, script string, stdin []byte) []byte {
	t.Helper()
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv is not installed")
	}
	cmd := exec.CommandContext(t.Context(), "uv", "run", "--quiet", "--with", pinnedMitmproxy, "python", "-c", script)
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("running the pinned mitmproxy: %v\n%s", err, stderr.String())
	}
	return out
}

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
			want := runPython(t, migrateScript, testutil.Fixture(t, rel))
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
