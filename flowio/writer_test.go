// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowio

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
	"github.com/zchee/mitmproxy-go/internal/state"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// writeAll writes flows into a flow file.
func writeAll(t *testing.T, flows []flow.Flow) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := NewWriter(&buf)
	for i, f := range flows {
		if err := w.Add(f); err != nil {
			t.Fatalf("flow %d: %v", i, err)
		}
	}
	return buf.Bytes()
}

// readableFixtures lists every flow file fixture the reader accepts: the
// files in mitmproxy/flows, found by listing the directory so that a
// fixture added later is covered, and dumpfile-19.mitm.
func readableFixtures(t *testing.T) []string {
	t.Helper()
	const dir = "mitmproxy/flows"
	paths, err := filepath.Glob(filepath.Join(testutil.FixturePath(t, dir), "*.mitm"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no .mitm fixtures in testdata/%s", dir)
	}
	rels := []string{"mitmproxy/dumpfile-19.mitm"}
	for _, p := range paths {
		rels = append(rels, dir+"/"+filepath.Base(p))
	}
	return rels
}

// TestReadWriteRead checks that writing what was read and reading it back
// yields the same flows, and that the written file is in the current
// format with every dictionary written in mitmproxy's order.
func TestReadWriteRead(t *testing.T) {
	for _, rel := range readableFixtures(t) {
		t.Run(rel, func(t *testing.T) {
			first, err := readAll(t, testutil.Fixture(t, rel))
			if err != nil {
				t.Fatal(err)
			}
			written := writeAll(t, first)
			second, err := readAll(t, written)
			if err != nil {
				t.Fatalf("reading the written file: %v", err)
			}
			if len(second) != len(first) {
				t.Fatalf("read back %d flows, want %d", len(second), len(first))
			}
			for i := range first {
				want, got := first[i].GetState(), second[i].GetState()
				if !state.Equal(want, got) {
					t.Errorf("flow %d: state changed through a write and a read:\nwant %v\n got %v", i, want, got)
				}
			}

			raw := rawFlowsOf(t, written)
			for i, m := range raw {
				if v, _ := m.Get("version"); v != int64(flow.FormatVersion) {
					t.Errorf("flow %d: written with version %v, want %d", i, v, flow.FormatVersion)
				}
				// The file holds get_state's keys reversed.
				keys := first[i].GetState().Keys()
				reversed := make([]string, len(keys))
				for j, k := range keys {
					reversed[len(keys)-1-j] = k
				}
				if diff := gocmp.Diff(reversed, m.Keys()); diff != "" {
					t.Errorf("flow %d: written key order mismatch (-want +got):\n%s", i, diff)
				}
			}
			// Writing is deterministic: the second read writes the same
			// bytes as the first.
			if again := writeAll(t, second); !bytes.Equal(again, written) {
				t.Error("writing the read-back flows gave different bytes")
			}
		})
	}
}

// rawFlowsOf decodes the flows of a flow file without migrating them.
func rawFlowsOf(t *testing.T, b []byte) []*state.Map {
	t.Helper()
	var out []*state.Map
	for rest := b; len(rest) > 0; {
		v, r, err := tnetstring.Pop(rest)
		if err != nil {
			t.Fatal(err)
		}
		rest = r
		out = append(out, fromTnetstring(v).(*state.Map))
	}
	return out
}

// TestWriteByteIdentity checks Write(Read(file)) against the v21 fixture,
// which mitmproxy's own FlowWriter(FlowReader(file)) reproduces byte for
// byte; the difftest checks that against the pinned mitmproxy.
func TestWriteByteIdentity(t *testing.T) {
	b := testutil.Fixture(t, v21Fixture)
	flows, err := readAll(t, b)
	if err != nil {
		t.Fatal(err)
	}
	if got := writeAll(t, flows); !bytes.Equal(got, b) {
		t.Errorf("Write(Read(%s)) differs from the file:\nwant %q\n got %q", v21Fixture, b, got)
	}
}

func TestWriterErrors(t *testing.T) {
	flows, err := readAll(t, testutil.Fixture(t, v21Fixture))
	if err != nil {
		t.Fatal(err)
	}
	f := flows[0]

	boom := errors.New("boom")
	if err := NewWriter(failingWriter{boom}).Add(f); !errors.Is(err, boom) {
		t.Errorf("Add error = %v, want %v", err, boom)
	}

	f.Common().Comment = "\xff"
	var buf bytes.Buffer
	err = NewWriter(&buf).Add(f)
	if err == nil || !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Errorf("Add of an invalid UTF-8 comment: error = %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("a failed Add wrote %d bytes", buf.Len())
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestToTnetstring(t *testing.T) {
	var nilMap *state.Map
	got := toTnetstring([]any{nilMap, dictOf("a", []any{dictOf("b", int64(1))}), "s"})
	enc, err := tnetstring.Dumps(got)
	if err != nil {
		t.Fatal(err)
	}
	if want := "30:0:~19:1:a;11:8:1:b;1:1#}]}1:s;]"; string(enc) != want {
		t.Errorf("encoding = %q, want %q", enc, want)
	}
}
