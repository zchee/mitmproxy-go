// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tnetstring

import (
	"bytes"
	"fmt"
	"math"
	rand "math/rand/v2"
	"strconv"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/omap"
)

// diffScript reads float64 bit patterns as hex, one per line, and writes
// tnetstring.dumps of each float on its own line, followed by the dumps of a
// dict mapping each line number to its float.
const diffScript = `
import struct, sys
from mitmproxy.io import tnetstring
floats = [struct.unpack(">d", bytes.fromhex(line))[0] for line in sys.stdin.read().split()]
out = sys.stdout.buffer
for f in floats:
    out.write(tnetstring.dumps(f) + b"\n")
out.write(tnetstring.dumps({str(i): f for i, f in enumerate(floats)}))
`

// randomFloats returns n floats drawn from several distributions, so that
// both notations, the switch points between them, denormals and
// non-finite values are all exercised.
func randomFloats(n int) []float64 {
	r := rand.New(rand.NewPCG(20261005, 3368))
	out := []float64{0, math.Copysign(0, -1), math.Inf(1), math.Inf(-1), math.NaN(), 1e16, 1e-5, 1e-4, 9999999999999998, 5e-324}
	for len(out) < n {
		var f float64
		switch r.IntN(5) {
		case 0: // Any bit pattern.
			f = math.Float64frombits(r.Uint64())
		case 1: // Unix timestamps with microseconds, as flows store them.
			f = 1.5e9 + r.Float64()*5e8
		case 2: // Around the positional/scientific boundaries.
			f = r.Float64() * math.Pow10(r.IntN(8)-6+r.IntN(2)*18)
		case 3: // Integral values near 2^53 and 1e16.
			f = float64(int64(1<<53) - 100 + r.Int64N(1e16))
		default: // Wide exponent range.
			f = (r.Float64() - 0.5) * math.Pow10(r.IntN(617)-308)
		}
		out = append(out, f)
	}
	return out[:n]
}

func TestDifferentialFloats(t *testing.T) {
	floats := randomFloats(1000)
	var in strings.Builder
	for _, f := range floats {
		fmt.Fprintf(&in, "%016x\n", math.Float64bits(f))
	}
	out := difftest.Python(t, diffScript, []byte(in.String()))

	lines := bytes.SplitN(out, []byte("\n"), len(floats)+1)
	if len(lines) != len(floats)+1 {
		t.Fatalf("got %d output lines, want %d", len(lines), len(floats)+1)
	}
	d := omap.NewWithCapacity[any](len(floats))
	for i, f := range floats {
		got, err := Dumps(f)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, lines[i]) {
			t.Errorf("float %d (bits %016x): Go %q, Python %q", i, math.Float64bits(f), got, lines[i])
		}
		d.Set(strconv.Itoa(i), f)
	}
	got, err := Dumps(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, lines[len(floats)]) {
		t.Errorf("dict of all floats differs from Python's encoding (Go %d bytes, Python %d bytes)", len(got), len(lines[len(floats)]))
	}
}
