// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowio

import (
	"bytes"
	"io"
	"testing"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// benchFixture is a flow file mitmproxy wrote, with HTTP flows of varied
// sizes, so that the benchmarks measure a whole file rather than one value.
const benchFixture = "mitmproxy/flows/diff_data.mitm"

// BenchmarkRead measures decoding a flow file into flows: the tnetstring
// reader, format migration and the models' SetState.
func BenchmarkRead(b *testing.B) {
	data := testutil.Fixture(b, benchFixture)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		n := 0
		for _, err := range NewReader(bytes.NewReader(data)).All() {
			if err != nil {
				b.Fatal(err)
			}
			n++
		}
		if n == 0 {
			b.Fatal("no flows read")
		}
	}
}

// BenchmarkWrite measures encoding flows into a flow file: the models'
// GetState and the tnetstring writer.
func BenchmarkWrite(b *testing.B) {
	data := testutil.Fixture(b, benchFixture)
	var flows []flow.Flow
	for f, err := range NewReader(bytes.NewReader(data)).All() {
		if err != nil {
			b.Fatal(err)
		}
		flows = append(flows, f)
	}
	var size int64
	w := NewWriter(countingWriter{&size})
	for _, f := range flows {
		if err := w.Add(f); err != nil {
			b.Fatal(err)
		}
	}
	b.SetBytes(size)
	b.ReportAllocs()
	w = NewWriter(io.Discard)
	for b.Loop() {
		for _, f := range flows {
			if err := w.Add(f); err != nil {
				b.Fatal(err)
			}
		}
	}
}

type countingWriter struct{ n *int64 }

func (w countingWriter) Write(p []byte) (int, error) {
	*w.n += int64(len(p))
	return len(p), nil
}
