// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layertest_test

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func TestMemoryPipeHalfClose(t *testing.T) {
	tests := map[string]struct{ reverse bool }{
		"success: first endpoint closes write":  {},
		"success: second endpoint closes write": {reverse: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, b := layertest.MemoryPipe(t)
			if tt.reverse {
				a, b = b, a
			}
			done := make(chan error, 1)
			go func() {
				_, err := io.WriteString(a, "request")
				done <- errors.Join(err, a.CloseWrite())
			}()
			got, err := io.ReadAll(b)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff("request", string(got)); diff != "" {
				t.Fatalf("request (-want +got):\n%s", diff)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if _, err := a.Write([]byte("closed")); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("write after CloseWrite: %v", err)
			}
			go func() {
				_, err := io.WriteString(b, "response")
				done <- errors.Join(err, b.CloseWrite())
			}()
			got, err = io.ReadAll(a)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff("response", string(got)); diff != "" {
				t.Fatalf("response after half-close (-want +got):\n%s", diff)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMemoryPipeSegmentation(t *testing.T) {
	tests := map[string]struct{ parts []string }{
		"success: fragmented length field": {parts: []string{"\x00", "\x03abc"}},
		"success: fragmented body":         {parts: []string{"\x00\x03a", "bc"}},
		"success: fragmented next length":  {parts: []string{"\x00\x01a\x00", "\x01b"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, b := layertest.MemoryPipe(t)
			done := make(chan error, 1)
			go func() {
				for _, part := range tt.parts {
					if _, err := io.WriteString(a, part); err != nil {
						done <- err
						return
					}
				}
				done <- a.CloseWrite()
			}()
			var got []string
			var buf [64]byte
			for {
				n, err := b.Read(buf[:])
				if n != 0 {
					got = append(got, string(buf[:n]))
				}
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if diff := gocmp.Diff(tt.parts, got); diff != "" {
				t.Fatalf("read boundaries (-want +got):\n%s", diff)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMemoryPipeDeadlines(t *testing.T) {
	tests := map[string]struct {
		deadline func(layer.Conn, time.Time) error
		operate  func(layer.Conn) error
	}{
		"error: read deadline": {
			deadline: layer.Conn.SetReadDeadline,
			operate:  func(c layer.Conn) error { _, err := c.Read(make([]byte, 1)); return err },
		},
		"error: write deadline": {
			deadline: layer.Conn.SetWriteDeadline,
			operate:  func(c layer.Conn) error { _, err := c.Write([]byte("x")); return err },
		},
		"error: combined read deadline": {
			deadline: layer.Conn.SetDeadline,
			operate:  func(c layer.Conn) error { _, err := c.Read(make([]byte, 1)); return err },
		},
		"error: combined write deadline": {
			deadline: layer.Conn.SetDeadline,
			operate:  func(c layer.Conn) error { _, err := c.Write([]byte("x")); return err },
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, _ := layertest.MemoryPipe(t)
			done := make(chan error, 1)
			go func() { done <- tt.operate(a) }()
			if err := tt.deadline(a, time.Now()); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("operation: %v, want deadline exceeded", err)
				}
			case <-t.Context().Done():
				t.Fatal(t.Context().Err())
			}
		})
	}
}

func TestMemoryPipeClose(t *testing.T) {
	tests := map[string]struct {
		operate func(layer.Conn) error
	}{
		"error: close interrupts read": {
			operate: func(c layer.Conn) error { _, err := c.Read(make([]byte, 1)); return err },
		},
		"error: close interrupts write": {
			operate: func(c layer.Conn) error { _, err := c.Write([]byte("x")); return err },
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, _ := layertest.MemoryPipe(t)
			done := make(chan error, 1)
			go func() { done <- tt.operate(a) }()
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("operation after close: %v", err)
			}
			if err := a.Close(); err != nil {
				t.Fatalf("repeated close: %v", err)
			}
		})
	}
}
