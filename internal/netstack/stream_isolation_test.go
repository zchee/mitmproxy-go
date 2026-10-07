// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"

	"go.uber.org/goleak"
)

// Independent net.Pipe peers isolate the writer queues from packet forwarding.
func TestStreamWriterIsolation(t *testing.T) {
	defer goleak.VerifyNone(t)
	tests := map[string]struct{ siblingBytes int }{
		"small sibling":        {siblingBytes: 12},
		"buffer-sized sibling": {siblingBytes: tcpBufferSize},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				blockedConn, blockedPeer := net.Pipe()
				defer func() { _ = blockedPeer.Close() }()
				activeConn, activePeer := net.Pipe()
				defer func() { _ = activePeer.Close() }()
				blocked := newStream(ctx, blockedConn, nil, nil)
				active := newStream(ctx, activeConn, nil, nil)
				defer func() { cancel(); <-blocked.done; <-active.done }()
				if _, err := blocked.Write(make([]byte, maxPendingBytes)); err != nil {
					t.Fatal(err)
				}
				blockedResult := make(chan error, 1)
				go func() { _, err := blocked.Write([]byte("waiting")); blockedResult <- err }()
				synctest.Wait()
				select {
				case err := <-blockedResult:
					t.Fatalf("expected blocked writer: %v", err)
				default:
				}
				want := bytes.Repeat([]byte("x"), tt.siblingBytes)
				if n, err := active.Write(want); n != len(want) || err != nil {
					t.Fatalf("sibling write = %d, %v", n, err)
				}
				if err := active.Close(); err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(activePeer)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("sibling bytes = %d, %v", len(got), err)
				}
				select {
				case err := <-blockedResult:
					t.Fatalf("sibling changed blocked writer: %v", err)
				default:
				}
				cancel()
				if err := <-blockedResult; !errors.Is(err, context.Canceled) {
					t.Fatalf("blocked writer cancellation = %v", err)
				}
			})
		})
	}
}

func TestStreamCloseWakesRead(t *testing.T) {
	defer goleak.VerifyNone(t)
	tests := map[string]struct{ half bool }{
		"close":       {},
		"close write": {half: true},
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
				result := make(chan error, 1)
				go func() { _, err := s.Read(make([]byte, 1)); result <- err }()
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
				if err := <-result; !errors.Is(err, net.ErrClosed) {
					t.Fatalf("blocked read = %v", err)
				}
			})
		})
	}
}
