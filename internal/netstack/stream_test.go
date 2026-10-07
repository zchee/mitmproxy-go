// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/goleak"
)

func TestStreamBufferedWrite(t *testing.T) {
	defer goleak.VerifyNone(t)
	tests := map[string]struct{ half bool }{
		"full close flushes": {},
		"half close flushes": {half: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				conn, peer := net.Pipe()
				defer func() { _ = peer.Close() }()
				s := newStream(ctx, conn, nil, nil)
				defer func() { cancel(); <-s.done }()
				payload := []byte("hello world!")
				if n, err := s.Write(payload); n != len(payload) || err != nil {
					t.Fatalf("Write = %d, %v", n, err)
				}
				clear(payload)
				// The peer has not read: a returned Write proves below-cap nonblocking admission.
				synctest.Wait()
				var err error
				if tt.half {
					err = s.CloseWrite()
				} else {
					err = s.Close()
				}
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(peer)
				if err != nil || !bytes.Equal(got, []byte("hello world!")) {
					t.Fatalf("flushed bytes = %q, %v", got, err)
				}
				if _, err := s.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("write after close = %v", err)
				}
				if _, err := s.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("read after close = %v", err)
				}
			})
		})
	}
}

func TestStreamWriteBackpressure(t *testing.T) {
	defer goleak.VerifyNone(t)
	tests := map[string]struct{ release string }{
		"space wakes writer":    {release: "space"},
		"deadline wakes writer": {release: "deadline"},
		"close wakes writer":    {release: "close"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				conn, peer := net.Pipe()
				defer func() { _ = peer.Close() }()
				s := newStream(ctx, conn, nil, nil)
				defer func() { cancel(); <-s.done }()
				if _, err := s.Write(make([]byte, maxPendingBytes)); err != nil {
					t.Fatal(err)
				}
				result := make(chan error, 1)
				go func() { _, err := s.Write([]byte("x")); result <- err }()
				synctest.Wait()
				select {
				case err := <-result:
					t.Fatalf("cap did not block: %v", err)
				default:
				}
				switch tt.release {
				case "space":
					if _, err := io.CopyN(io.Discard, peer, maxPendingBytes); err != nil {
						t.Fatal(err)
					}
					if err := <-result; err != nil {
						t.Fatal(err)
					}
					b := make([]byte, 1)
					if _, err := io.ReadFull(peer, b); err != nil || b[0] != 'x' {
						t.Fatalf("queued byte = %q, %v", b, err)
					}
				case "deadline":
					if err := s.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
						t.Fatal(err)
					}
					time.Sleep(time.Second)
					if err := <-result; !errors.Is(err, os.ErrDeadlineExceeded) {
						t.Fatalf("write deadline = %v", err)
					}
				case "close":
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					if err := <-result; !errors.Is(err, net.ErrClosed) {
						t.Fatalf("write close = %v", err)
					}
				}
			})
		})
	}
}

func TestStreamDrain(t *testing.T) {
	defer goleak.VerifyNone(t)
	tests := map[string]struct{ cancel bool }{
		"peer reads":     {},
		"caller cancels": {cancel: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, stop := context.WithCancel(t.Context())
				defer stop()
				conn, peer := net.Pipe()
				defer func() { _ = peer.Close() }()
				s := newStream(ctx, conn, nil, nil)
				defer func() { stop(); <-s.done }()
				if _, err := s.Write([]byte("buffered")); err != nil {
					t.Fatal(err)
				}
				drainCtx, cancel := context.WithCancel(t.Context())
				defer cancel()
				result := make(chan error, 1)
				go func() { result <- s.Drain(drainCtx) }()
				synctest.Wait()
				select {
				case err := <-result:
					t.Fatalf("Drain did not wait: %v", err)
				default:
				}
				if tt.cancel {
					cancel()
					if err := <-result; !errors.Is(err, context.Canceled) {
						t.Fatalf("Drain = %v", err)
					}
				} else {
					if _, err := io.CopyN(io.Discard, peer, 8); err != nil {
						t.Fatal(err)
					}
					if err := <-result; err != nil {
						t.Fatal(err)
					}
				}
			})
		})
	}
}
