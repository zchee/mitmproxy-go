// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGRPCFrames(t *testing.T) {
	tests := map[string]struct {
		data     []byte
		encoding string
		want     [][]byte
	}{
		"empty": {},
		"two messages": {
			data: []byte{0, 0, 0, 0, 3, 8, 150, 1, 0, 0, 0, 0, 3, 8, 150, 1},
			want: [][]byte{{8, 150, 1}, {8, 150, 1}},
		},
		"gzip": {
			data:     []byte{1, 0, 0, 0, 23, 31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 227, 152, 198, 8, 0, 160, 149, 78, 161, 3, 0, 0, 0},
			encoding: "gzip",
			want:     [][]byte{{8, 150, 1}},
		},
		"deflate": {
			data:     []byte{1, 0, 0, 0, 5, 227, 152, 198, 8, 0},
			encoding: "deflate",
			want:     [][]byte{{8, 150, 1}},
		},
		"identity": {
			data:     []byte{1, 0, 0, 0, 3, 8, 150, 1},
			encoding: "identity",
			want:     [][]byte{{8, 150, 1}},
		},
		"uncompressed ignores encoding": {
			data:     []byte{0, 0, 0, 0, 3, 8, 150, 1},
			encoding: "unsupported",
			want:     [][]byte{{8, 150, 1}},
		},
		"empty message": {
			data: []byte{0, 0, 0, 0, 0},
			want: [][]byte{{}},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			original := bytes.Clone(tt.data)
			var got [][]byte
			err := walkGRPC(tt.data, tt.encoding, &viewBudget{view: "gRPC"}, func(payload []byte) error {
				got = append(got, bytes.Clone(payload))
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("frame payloads (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(original, tt.data); diff != "" {
				t.Fatalf("input mutation (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGRPCFrameErrors(t *testing.T) {
	tests := map[string]struct {
		data     []byte
		encoding string
	}{
		"short header":         {data: []byte{0, 0, 0, 0}},
		"invalid flag":         {data: []byte{2, 0, 0, 0, 0}},
		"short body":           {data: []byte{0, 0, 0, 0, 2, 1}},
		"length overflow":      {data: []byte{0, 255, 255, 255, 255}},
		"unsupported encoding": {data: []byte{1, 0, 0, 0, 0}, encoding: "zstd"},
		"corrupt gzip":         {data: []byte{1, 0, 0, 0, 1, 0}, encoding: "gzip"},
		"corrupt deflate":      {data: []byte{1, 0, 0, 0, 1, 7}, encoding: "deflate"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			visited := 0
			err := walkGRPC(tt.data, tt.encoding, &viewBudget{view: "gRPC"}, func([]byte) error {
				visited++
				return nil
			})
			if err == nil || visited != 0 {
				t.Fatalf("malformed input returned error=%v, visited=%d", err, visited)
			}
		})
	}
}

func TestGRPCFrameLimits(t *testing.T) {
	tests := map[string]struct {
		data     []byte
		encoding string
		budget   viewBudget
		visited  int
	}{
		"shared frames": {
			data:    []byte{0, 0, 0, 0, 2, 8, 1, 0, 0, 0, 0, 2, 8, 2},
			budget:  viewBudget{view: "gRPC", expanded: maxViewBytes - 3},
			visited: 1,
		},
		"compressed expansion": {
			data:     []byte{1, 0, 0, 0, 5, 227, 152, 198, 8, 0},
			encoding: "deflate",
			budget:   viewBudget{view: "gRPC", expanded: maxViewBytes - 2},
		},
		"shared node budget": {
			data:   []byte{0, 0, 0, 0, 0},
			budget: viewBudget{view: "gRPC", nodes: maxViewNodes},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			visited := 0
			err := walkGRPC(tt.data, tt.encoding, &tt.budget, func([]byte) error {
				visited++
				return nil
			})
			if _, ok := errors.AsType[*LimitError](err); !ok || visited != tt.visited {
				t.Fatalf("got error=%v, visited=%d; want typed limit and %d visits", err, visited, tt.visited)
			}
		})
	}
	writer := grpcExpansionWriter{budget: &viewBudget{expanded: maxViewBytes - 1}}
	if n, err := writer.Write([]byte{1, 2}); n != 0 || err == nil || writer.buffer.Len() != 0 {
		t.Fatalf("limit wrote %d bytes, buffer=%d, error=%v", n, writer.buffer.Len(), err)
	}
}

func TestGRPCFrameEncode(t *testing.T) {
	var got []byte
	var err error
	budget := &viewBudget{view: "gRPC"}
	for range 2 {
		got, err = appendGRPCFrame(got, []byte{8, 150, 1}, budget)
		if err != nil {
			t.Fatal(err)
		}
	}
	want := []byte{0, 0, 0, 0, 3, 8, 150, 1, 0, 0, 0, 0, 3, 8, 150, 1}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("framed bytes (-want +got):\n%s", diff)
	}
	budget.bytes = maxViewBytes - 4
	if out, err := appendGRPCFrame(got, nil, budget); err == nil || out != nil {
		t.Fatalf("output bound got %x, %v", out, err)
	}
}

func TestGRPCFrameCallbackError(t *testing.T) {
	want := errors.New("stop")
	calls := 0
	err := walkGRPC([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "", &viewBudget{}, func([]byte) error {
		calls++
		return want
	})
	if !errors.Is(err, want) || calls != 1 {
		t.Fatalf("callback error got %v after %d calls", err, calls)
	}
}
