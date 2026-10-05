// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

type memoryConn struct {
	net.Conn
	input io.Reader
}

func (c memoryConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c memoryConn) CloseWrite() error          { return nil }

type emptyReader struct{ calls int }

func (r *emptyReader) Read([]byte) (int, error) { r.calls++; return 0, nil }

func TestRecorderReplay(t *testing.T) {
	tests := map[string]struct{ read, peek int }{
		"read then peek": {3, 2},
		"peek only":      {0, 4},
		"read only":      {5, 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := Record(memoryConn{input: bytes.NewBufferString("abcdefgh")})
			if _, err := io.ReadFull(r, make([]byte, tt.read)); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Peek(tt.peek); err != nil {
				t.Fatal(err)
			}
			r.StopRecording()
			r.StopRecording()
			p, err := r.Peek(8)
			if err != nil {
				t.Fatal(err)
			}
			if string(p) != "abcdefgh" {
				t.Fatalf("peek across replay = %q", p)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff("abcdefgh", string(got)); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestRecorderBound(t *testing.T) {
	r := Record(memoryConn{input: bytes.NewReader(bytes.Repeat([]byte{'x'}, MaxRecordBytes+1))})
	if _, err := r.Peek(-1); !errors.Is(err, ErrRecordSize) {
		t.Fatalf("negative peek: %v", err)
	}
	if _, err := r.Peek(MaxRecordBytes + 1); !errors.Is(err, ErrRecordSize) {
		t.Fatalf("oversized peek: %v", err)
	}
	if n, err := io.CopyN(io.Discard, r, MaxRecordBytes); err != nil || n != MaxRecordBytes {
		t.Fatalf("read: %d, %v", n, err)
	}
	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, ErrRecordSize) {
		t.Fatalf("over cap: %v", err)
	}
	r.StopRecording()
	p, err := io.ReadAll(r)
	if err != nil || len(p) != MaxRecordBytes+1 {
		t.Fatalf("replay: %d, %v", len(p), err)
	}
}

func TestRecorderNoProgress(t *testing.T) {
	reader := &emptyReader{}
	r := Record(memoryConn{input: reader})
	if _, err := r.Peek(1); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("empty reads: %v", err)
	}
	if reader.calls != 100 {
		t.Fatalf("read count = %d, want 100", reader.calls)
	}
}

func TestRecorderReadByteAtATime(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	done := make(chan error, 1)
	go func() {
		for _, c := range []byte("firstsecond") {
			if _, err := b.Write([]byte{c}); err != nil {
				done <- err
				return
			}
		}
		done <- b.Close()
	}()
	type result struct {
		data []byte
		err  error
	}
	read := make(chan result, 1)
	go func() {
		r := Record(memoryConn{Conn: a, input: a})
		if _, err := io.ReadFull(r, make([]byte, 5)); err != nil {
			read <- result{err: err}
			return
		}
		r.StopRecording()
		data, err := io.ReadAll(r)
		read <- result{data, err}
	}()
	got := await(t, read)
	if got.err != nil {
		t.Fatal(got.err)
	}
	if string(got.data) != "firstsecond" {
		t.Fatalf("replay: %q", got.data)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}
