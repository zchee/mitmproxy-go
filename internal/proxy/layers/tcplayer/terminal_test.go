// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tcplayer

import (
	"context"
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestTerminalHooksReleaseInterception(t *testing.T) {
	tests := map[string]struct {
		cancel, interceptMessage, openError bool
	}{
		"orderly close":              {},
		"cancel":                     {cancel: true},
		"cancel intercepted message": {cancel: true, interceptMessage: true},
		"open failure":               {openError: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			intercepted := make(chan struct{})
			terminal := func(ctx context.Context, f *flow.TCPFlow) error {
				if deadline, ok := ctx.Deadline(); !ok || deadline.IsZero() || ctx.Err() != nil || ctx.Done() == nil {
					t.Error("terminal hook context lacks an active cleanup deadline")
				}
				f.Intercept()
				return nil
			}
			a := &observer{started: make(chan *flow.TCPFlow, 1), end: terminal, failed: terminal}
			if test.interceptMessage {
				a.message = func(_ context.Context, f *flow.TCPFlow) error {
					f.Intercept()
					close(intercepted)
					return nil
				}
			}
			s := newSession(t, a)
			wantErr := errors.New("connection refused")
			if test.openError {
				s.context.Server = nil
				s.context.Pool = openPool{open: func(context.Context, *connection.Server, layer.OpenOptions) (layer.Conn, *connection.Server, error) {
					return nil, nil, wantErr
				}}
			}
			s.start(t)
			await(t, a.started)
			want := []string{"tcp_start"}
			if test.interceptMessage {
				if _, err := s.client.Write([]byte("held")); err != nil {
					t.Fatal(err)
				}
				await(t, intercepted)
				want = append(want, "tcp_message")
			}
			if test.cancel {
				s.cancel()
			} else if !test.openError {
				if err := s.client.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if err := s.server.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			err := await(t, s.done)
			switch {
			case test.openError:
				if !errors.Is(err, wantErr) {
					t.Fatalf("open error = %v", err)
				}
				want = append(want, "tcp_error")
			case test.cancel:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel error = %v", err)
				}
				want = append(want, "tcp_end")
			default:
				if err != nil {
					t.Fatal(err)
				}
				want = append(want, "tcp_end")
			}
			if diff := gocmp.Diff(want, a.events); diff != "" {
				t.Fatal(diff)
			}
			if a.flow.Live || a.flow.Intercepted() {
				t.Fatal("terminal flow is still live or intercepted")
			}
		})
	}
}

func TestTerminalWriteFailureClassification(t *testing.T) {
	tests := map[string]struct {
		halfClose bool
		terminal  string
	}{
		"relay write failure":      {terminal: "tcp_error"},
		"close after peer closure": {halfClose: true, terminal: "tcp_end"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, nil)
			s.context.Server = failingWriter{Recorder: s.context.Server, halfClose: test.halfClose}
			s.start(t)
			want := []string{"tcp_start"}
			if test.halfClose {
				if err := s.client.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := s.client.Write([]byte("payload")); err != nil {
					t.Fatal(err)
				}
				want = append(want, "tcp_message")
			}
			if err := await(t, s.done); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("write error = %v, want preserved closed-pipe error", err)
			}
			want = append(want, test.terminal)
			if diff := gocmp.Diff(want, s.observed.events); diff != "" {
				t.Fatal(diff)
			}
			if s.observed.flow.Live {
				t.Fatal("finished flow remains live")
			}
			if got := s.observed.flow.Error != nil; got == test.halfClose {
				t.Errorf("flow error recorded = %t, want %t", got, !test.halfClose)
			}
		})
	}
}

type failingWriter struct {
	layer.Recorder
	halfClose bool
}

func (c failingWriter) Write(p []byte) (int, error) {
	if c.halfClose {
		return c.Recorder.Write(p)
	}
	return 0, io.ErrClosedPipe
}

func (c failingWriter) CloseWrite() error {
	if c.halfClose {
		return io.ErrClosedPipe
	}
	return c.Recorder.CloseWrite()
}
