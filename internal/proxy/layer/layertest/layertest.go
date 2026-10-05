// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package layertest checks protocol layers' replay, half-close and hook
// dispatch contracts using real connections.
package layertest

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// Timeout is a hang detector, never a performance assertion.
const Timeout = 30 * time.Second

// Session describes one fresh instance of the implementation under test.
// For a framing or encrypted protocol the fixture supplies peers that expose
// the protocol's payload stream, and inputs at the matching handover boundary.
// All sockets and background work must be registered with t.Cleanup.
type Session struct {
	// Client and Server are the peer ends driven by the test.
	Client, Server layer.Conn
	// ClientInput and ServerInput are the recording conns Run consumes.
	ClientInput, ServerInput layer.Recorder
	// ClientData and ServerData are valid payloads forwarded unchanged.
	ClientData, ServerData []byte
	// Run starts the real layer stack and returns when both directions end.
	Run func(context.Context) error
}

// Conformance runs both half-close directions, with and without a recorded
// prefix. setup must return a new real implementation per subtest. It also
// rejects direct Hook and HookFunc calls in the calling package's non-test
// source: layers dispatch through layer.Hooks instead of addon.Manager.
// Run this suite without t.Parallel so its goroutine-leak check is meaningful.
func Conformance(t *testing.T, setup func(*testing.T) Session) {
	t.Helper()
	NoDirectHooks(t)
	tests := map[string]struct{ clientFirst, replay bool }{
		"client half-close": {true, false},
		"server half-close": {false, false},
		"client replay":     {true, true},
		"server replay":     {false, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			baseline := goleak.IgnoreCurrent()
			t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
			s := setup(t)
			if len(s.ClientData) == 0 || len(s.ServerData) == 0 {
				t.Fatal("conformance payloads must be non-empty")
			}
			first, second := s.Client, s.Server
			input := s.ClientInput
			out, reply := s.ClientData, s.ServerData
			if !tt.clientFirst {
				first, second, input, out, reply = second, first, s.ServerInput, reply, out
			}
			ctx, cancel := context.WithTimeout(t.Context(), Timeout)
			defer cancel()
			stop := context.AfterFunc(ctx, func() { _ = s.Client.Close(); _ = s.Server.Close() })
			defer stop()
			written := make(chan error, 1)
			go func() { _, err := first.Write(out); written <- err }()
			if tt.replay {
				// One-byte reads model a fragmented sniff without hiding bytes
				// in a bufio.Reader that the child cannot access.
				for i := range len(out) {
					var b [1]byte
					if _, err := io.ReadFull(input, b[:]); err != nil {
						fail(t, "record prefix", err)
					}
					if b[0] != out[i] {
						t.Fatalf("record byte %d = %x, want %x", i, b[0], out[i])
					}
				}
			}
			s.ClientInput.StopRecording()
			s.ServerInput.StopRecording()
			done := make(chan error, 1)
			go func() { done <- s.Run(ctx) }()
			if err := receive(t, written); err != nil {
				fail(t, "write first payload", err)
			}
			if err := first.CloseWrite(); err != nil {
				fail(t, "first CloseWrite", err)
			}
			got, err := io.ReadAll(second)
			if err != nil {
				fail(t, "first EOF", err)
			}
			if diff := gocmp.Diff(out, got); diff != "" {
				t.Fatalf("first payload (-want +got):\n%s", diff)
			}
			go func() {
				_, err := second.Write(reply)
				if err == nil {
					err = second.CloseWrite()
				}
				written <- err
			}()
			got, err = io.ReadAll(first)
			if err != nil {
				fail(t, "reverse EOF", err)
			}
			if diff := gocmp.Diff(reply, got); diff != "" {
				t.Fatalf("reverse payload (-want +got):\n%s", diff)
			}
			if err := receive(t, written); err != nil {
				fail(t, "reverse write", err)
			}
			if err := receive(t, done); err != nil {
				fail(t, "layer return", err)
			}
		})
	}
}

func fail(t testing.TB, what string, err error) {
	t.Helper()
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	t.Fatalf("%s: %v\n%s", what, err, buf[:n])
}

func receive[T any](t testing.TB, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(Timeout):
		fail(t, "wait", context.DeadlineExceeded)
	}
	var zero T
	return zero
}

// NoDirectHooks rejects direct manager dispatch in non-test source files of
// the working package. It checks syntax, so comments and strings are ignored.
func NoDirectHooks(t testing.TB) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Clean(name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if ok && (sel.Sel.Name == "Hook" || sel.Sel.Name == "HookFunc") {
				t.Errorf("%s: layer must dispatch through Hooks.Fire or Hooks.FireFunc", fset.Position(sel.Pos()))
			}
			return true
		})
	}
}

// Pipe returns a real TCP socket pair with working half-close semantics.
// Both endpoints have generous hang-detector deadlines and close in cleanup.
func Pipe(t testing.TB) (a, b layer.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	type result struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan result, 1)
	go func() { c, err := listener.Accept(); accepted <- result{c, err} }()
	dialed, err := net.DialTimeout("tcp", listener.Addr().String(), Timeout)
	if err != nil {
		fail(t, "dial", err)
	}
	t.Cleanup(func() { _ = dialed.Close() })
	acc := receive(t, accepted)
	if acc.err != nil {
		fail(t, "accept", acc.err)
	}
	t.Cleanup(func() { _ = acc.conn.Close() })
	for _, c := range []net.Conn{dialed, acc.conn} {
		if err := c.SetDeadline(time.Now().Add(Timeout)); err != nil {
			fail(t, "set deadline", err)
		}
	}
	return dialed.(*net.TCPConn), acc.conn.(*net.TCPConn)
}
