// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build h2load

package httplayer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type loadCountedConn struct {
	net.Conn
	closes       atomic.Int64
	writeErr     error
	readErr      error
	prefix       []byte
	requestError bool
}

func (c *loadCountedConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func (c *loadCountedConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.requestError && len(p) >= 9 && p[3] == byte(http2.FrameHeaders) && p[8] == 3 {
		return 0, &net.OpError{Op: "write", Net: "tcp", Err: io.ErrClosedPipe}
	}
	return c.Conn.Write(p)
}

func (c *loadCountedConn) Read(p []byte) (int, error) {
	if c.prefix != nil {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			return n, c.readErr
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

type loadPartialConn struct {
	net.Conn
	remaining int
	partial   bool
}

func (c *loadPartialConn) Read(p []byte) (int, error) {
	if c.remaining == 0 {
		n, err := io.ReadFull(c.Conn, p[:9])
		if err == nil {
			c.remaining = int(p[0])<<16 | int(p[1])<<8 | int(p[2])
			c.partial = p[3] == byte(http2.FrameData) && binary.BigEndian.Uint32(p[5:9]) == 3
		}
		return n, err
	}
	if c.partial {
		n, err := io.ReadFull(c.Conn, p[:min(len(p), 4)])
		if err != nil {
			return n, err
		}
		return n, &net.OpError{Op: "read", Net: "tcp", Err: io.ErrUnexpectedEOF}
	}
	n, err := c.Conn.Read(p[:min(len(p), c.remaining)])
	c.remaining -= n
	return n, err
}

type loadAcceptFailure struct{ net.Listener }

func (l *loadAcceptFailure) Accept() (net.Conn, error) {
	return nil, &net.OpError{Op: "accept", Net: "tcp", Err: io.ErrClosedPipe}
}

func loadResponse(peer *loadHTTP2Peer, id uint32, size int64) error {
	if err := peer.headers(id, []hpack.HeaderField{{Name: ":status", Value: "200"}}, false); err != nil {
		return err
	}
	return peer.body(id, make([]byte, 128<<10), size)
}

func TestLoadDirectTerminalSidecar(t *testing.T) {
	tests := map[string]struct {
		options   loadDirectOptions
		phase     string
		outcome   string
		actual    int64
		validated *int64
	}{
		"error: origin accept delivered before ready": {phase: "direct-handshake", outcome: "failed", options: loadDirectOptions{listen: func() (net.Listener, error) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			return &loadAcceptFailure{Listener: listener}, nil
		}}},
		"error: real peer partial payload retains typed read cause": {phase: "direct-transfer", outcome: "protocol-failure", actual: 4, validated: new(int64(0)), options: loadDirectOptions{clientConn: func(c net.Conn) net.Conn { return &loadPartialConn{Conn: c} }}},
		"success: complete payload before teardown":                 {phase: "direct-transfer", outcome: "success", actual: 4096},
		"error: setup failure leaves peers unavailable": {phase: "setup", outcome: "failed", options: loadDirectOptions{listen: func() (net.Listener, error) {
			return nil, &net.OpError{Op: "listen", Net: "tcp", Err: io.ErrClosedPipe}
		}}},
		"error: warmup reset": {phase: "direct-warmup", outcome: "failed", options: loadDirectOptions{response: func(p *loadHTTP2Peer, id uint32, _ int64) error {
			return p.write(func(f *http2.Framer) error { return f.WriteRSTStream(id, http2.ErrCodeCancel) })
		}}},
		"error: stalled measured transfer": {phase: "direct-transfer", outcome: "measured-transfer-timeout", options: loadDirectOptions{response: func(p *loadHTTP2Peer, id uint32, size int64) error {
			if id == 1 {
				return loadResponse(p, id, size)
			}
			return nil
		}}},
		"error: slow progress measured transfer": {phase: "direct-transfer", outcome: "measured-transfer-timeout", actual: 4, options: loadDirectOptions{response: func(p *loadHTTP2Peer, id uint32, size int64) error {
			if id == 1 {
				return loadResponse(p, id, size)
			}
			return p.write(func(f *http2.Framer) error { return f.WriteData(id, false, []byte("slow")) })
		}}},
		"error: request write keeps typed cause": {phase: "direct-transfer", outcome: "failed", options: loadDirectOptions{clientConn: func(c net.Conn) net.Conn { return &loadCountedConn{Conn: c, requestError: true} }}},
		"error: measured stream reset": {phase: "direct-transfer", outcome: "protocol-failure", options: loadDirectOptions{response: func(p *loadHTTP2Peer, id uint32, size int64) error {
			if id == 1 {
				return loadResponse(p, id, size)
			}
			return p.write(func(f *http2.Framer) error { return f.WriteRSTStream(id, http2.ErrCodeCancel) })
		}}},
		"error: measured GOAWAY": {phase: "direct-transfer", outcome: "protocol-failure", options: loadDirectOptions{response: func(p *loadHTTP2Peer, id uint32, size int64) error {
			if id == 1 {
				return loadResponse(p, id, size)
			}
			return p.write(func(f *http2.Framer) error { return f.WriteGoAway(id, http2.ErrCodeProtocol, nil) })
		}}},
		"error: measured EOF": {phase: "direct-transfer", outcome: "protocol-failure", options: loadDirectOptions{response: func(p *loadHTTP2Peer, id uint32, size int64) error {
			if id == 1 {
				return loadResponse(p, id, size)
			}
			p.closeConn()
			return nil
		}}},
		"error: malformed DATA": {phase: "direct-transfer", outcome: "protocol-failure", options: loadDirectOptions{response: func(p *loadHTTP2Peer, id uint32, size int64) error {
			if id == 1 {
				return loadResponse(p, id, size)
			}
			return p.write(func(f *http2.Framer) error { return f.WriteRawFrame(http2.FrameData, 0, 0, []byte("bad")) })
		}}},
		"error: response worker cause": {phase: "direct-transfer", outcome: "protocol-failure", options: loadDirectOptions{response: func(p *loadHTTP2Peer, id uint32, size int64) error {
			if id == 1 {
				return loadResponse(p, id, size)
			}
			return &net.OpError{Op: "write", Net: "tcp", Err: io.ErrClosedPipe}
		}}},
		"error: peer context cancellation": {phase: "direct-transfer", outcome: "protocol-failure", options: loadDirectOptions{response: func(p *loadHTTP2Peer, id uint32, size int64) error {
			if id == 1 {
				return loadResponse(p, id, size)
			}
			p.cancel()
			return nil
		}}},
		"error: wrong completed stream": {phase: "direct-transfer", outcome: "failed", options: loadDirectOptions{response: func(p *loadHTTP2Peer, id uint32, size int64) error {
			if id == 1 {
				return loadResponse(p, id, size)
			}
			return p.write(func(f *http2.Framer) error { return f.WriteData(5, true, nil) })
		}}},
		"error: wrong complete byte count": {phase: "direct-transfer", outcome: "failed", actual: 4, options: loadDirectOptions{response: func(p *loadHTTP2Peer, id uint32, size int64) error {
			if id == 1 {
				return loadResponse(p, id, size)
			}
			return loadResponse(p, id, 4)
		}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("NETWORK_GATE_OUTPUT", root)
			tt.options.wait = 50 * time.Millisecond
			checked := false
			tt.options.beforeClose = func(s *loadDirectTerminal) {
				checked = true
				r, err := readLoadDirectReceipt(root)
				if err != nil {
					t.Error(err)
					return
				}
				if r.Client != nil && (r.Client.Done || r.Client.Context != nil) && r.Outcome == "success" {
					t.Error("success snapshot followed cleanup")
				}
				if r.Origin != nil && r.Origin.Context != nil && r.Outcome == "success" {
					t.Error("origin canceled before publication")
				}
				if s.path == "" {
					t.Error("publication did not create a path")
				}
			}
			elapsed, err := runLoadDirectDownload(t, 4096, 1<<20, tt.options)
			if (err == nil) != (tt.outcome == "success") {
				t.Fatalf("terminal error = %v, expected outcome %s", err, tt.outcome)
			}
			if !checked {
				t.Fatal("pre-close assertion not called")
			}
			r, err := readLoadDirectReceipt(root)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]string{"phase": r.Phase, "outcome": r.Outcome}
			want := map[string]string{"phase": tt.phase, "outcome": tt.outcome}
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Fatalf("terminal state (-want +got):\n%s", diff)
			}
			switch tt.phase {
			case "setup":
				if r.Client != nil || r.Origin != nil || r.Stream != nil || r.ElapsedNS != nil || r.ActualBytes != nil {
					t.Fatal("uncreated state was not unavailable")
				}
			case "direct-handshake":
				if r.Origin != nil || r.Stream != nil || r.ElapsedNS != nil || r.ActualBytes != nil {
					t.Fatal("failed accept published unavailable peer/stream state")
				}
			default:
				validated := tt.actual
				if tt.validated != nil {
					validated = *tt.validated
				}
				if r.ActualBytes == nil || r.ValidatedBytes == nil || *r.ActualBytes != tt.actual || *r.ValidatedBytes != validated {
					t.Fatalf("payload accounting: %+v", r)
				}
				if tt.phase == "direct-transfer" && (r.ElapsedNS == nil || *r.ElapsedNS != elapsed.Nanoseconds()) {
					t.Fatal("elapsed was not frozen at wait boundary")
				}
			}
		})
	}
	t.Run("success: sidecar readable to artifact collector", func(t *testing.T) {
		const childEnv = "MITMPROXY_GO_DIRECT_PERMISSIONS"
		if phase := os.Getenv(childEnv); phase != "" {
			root := os.Getenv("NETWORK_GATE_OUTPUT")
			if phase == "publish" {
				if _, err := runLoadDirectDownload(t, 4096, 1<<20, loadDirectOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := readLoadDirectReceipt(root); err != nil {
				t.Fatal(err)
			}
			paths, err := filepath.Glob(filepath.Join(root, "direct-terminal-*.json"))
			if err != nil || len(paths) != 1 {
				t.Fatalf("collector listing = %v, error = %v", paths, err)
			}
			info, err := os.Stat(paths[0])
			if err != nil {
				t.Fatal(err)
			}
			want := os.FileMode(0o644)
			if runtime.GOOS == "windows" {
				want = 0o666
			}
			if diff := gocmp.Diff(want, info.Mode().Perm()); diff != "" {
				t.Fatalf("sidecar permissions (-want +got):\n%s", diff)
			}
			return
		}
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		tests := map[string]struct{ umask string }{
			"success: publisher umask 022": {umask: "022"},
			"success: publisher umask 002": {umask: "002"},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				for _, phase := range []string{"publish", "collect"} {
					ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
					mask := tt.umask
					if phase == "collect" {
						mask = "077"
					}
					args := []string{"-test.run=^TestLoadDirectTerminalSidecar$/^success:_sidecar_readable_to_artifact_collector$", "-test.v"}
					cmd := exec.CommandContext(ctx, executable, args...)
					if runtime.GOOS != "windows" {
						args = append([]string{"-c", `umask "$1"; shift; exec "$@"`, "sh", mask, executable}, args...)
						cmd = exec.CommandContext(ctx, "sh", args...)
					}
					cmd.Env = append(os.Environ(), childEnv+"="+phase, "NETWORK_GATE_OUTPUT="+root)
					output, err := cmd.CombinedOutput()
					if writeErr := os.WriteFile(filepath.Join(root, phase+".log"), output, 0o600); writeErr != nil {
						cancel()
						t.Fatal(writeErr)
					}
					watchdog := ctx.Err()
					cancel()
					if err != nil || watchdog != nil {
						t.Fatalf("%s child: %v, watchdog=%v\n%s", phase, err, watchdog, output)
					}
				}
			})
		}
	})
	t.Run("error: write failure is explicit", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(file, []byte("occupied"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("NETWORK_GATE_OUTPUT", file)
		_, err := runLoadDirectDownload(t, 4096, 1<<20, loadDirectOptions{})
		if err == nil || !strings.Contains(err.Error(), "write direct terminal sidecar") {
			t.Fatalf("write failure = %v", err)
		}
	})
	t.Run("error: missing duplicate malformed and contradictory receipts", func(t *testing.T) {
		tests := map[string]struct {
			content   string
			duplicate bool
		}{
			"missing": {}, "malformed": {content: "{"}, "duplicate": {content: `{}`, duplicate: true},
			"contradictory": {content: `{"phase":"direct-transfer","outcome":"success","expected_bytes":10,"actual_bytes":5,"validated_bytes":5}`},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				if tt.content != "" {
					if err := os.WriteFile(filepath.Join(root, "direct-terminal-a.json"), []byte(tt.content), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if tt.duplicate {
					if err := os.WriteFile(filepath.Join(root, "direct-terminal-b.json"), []byte(tt.content), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := readLoadDirectReceipt(root); err == nil {
					t.Fatal("invalid receipt accepted")
				}
			})
		}
	})
}

func TestLoadDirectConstructionFailure(t *testing.T) {
	const childEnv = "MITMPROXY_GO_DIRECT_CONSTRUCTION"
	if mode := os.Getenv(childEnv); mode != "" {
		root := os.Getenv("NETWORK_GATE_OUTPUT")
		var count *loadCountedConn
		options := loadDirectOptions{wait: time.Second}
		switch mode {
		case "preface-write":
			options.clientConn = func(c net.Conn) net.Conn {
				count = &loadCountedConn{Conn: c, writeErr: &net.OpError{Op: "write", Net: "tcp", Err: io.ErrClosedPipe}}
				return count
			}
		case "short-preface":
			options.originConn = func(c net.Conn) net.Conn {
				count = &loadCountedConn{Conn: c, prefix: []byte("PRI"), readErr: io.EOF}
				return count
			}
		case "eof-preface":
			options.originConn = func(c net.Conn) net.Conn {
				count = &loadCountedConn{Conn: c, prefix: []byte{}, readErr: io.EOF}
				return count
			}
		case "malformed-preface":
			options.originConn = func(c net.Conn) net.Conn {
				count = &loadCountedConn{Conn: c, prefix: bytes.Repeat([]byte("x"), len(http2.ClientPreface))}
				return count
			}
		case "settings-write":
			options.originConn = func(c net.Conn) net.Conn {
				count = &loadCountedConn{Conn: c, writeErr: &net.OpError{Op: "write", Net: "tcp", Err: io.ErrClosedPipe}}
				return count
			}
		case "legacy-preface-write":
			a, b := net.Pipe()
			defer func() { _ = b.Close() }()
			count = &loadCountedConn{Conn: a, writeErr: io.ErrClosedPipe}
			t.Cleanup(func() {
				if count.closes.Load() != 1 {
					t.Errorf("close count=%d", count.closes.Load())
				}
			})
			newLoadHTTP2Peer(t, t.Context(), count, true, nil, nil)
			return
		default:
			t.Fatalf("unknown construction fixture %q", mode)
		}
		options.beforeClose = func(s *loadDirectTerminal) {
			r, err := readLoadDirectReceipt(root)
			if err != nil {
				t.Error(err)
				return
			}
			if count.closes.Load() != 0 {
				t.Error("connection closed before original-cause publication")
			}
			if r.Cause == nil {
				t.Error("constructor cause unavailable")
			}
			if mode != "preface-write" && (r.Origin == nil || r.Origin.Failure == nil) {
				t.Error("origin setup error not delivered to owner")
			}
			if mode != "settings-write" {
				peer := r.Origin
				if mode == "preface-write" {
					peer = r.Client
				}
				if peer == nil || peer.ReaderStarted {
					t.Error("failed preface started a reader")
				}
			}
		}
		_, err := runLoadDirectDownload(t, 4096, 1<<20, options)
		if err == nil {
			t.Fatal("construction succeeded")
		}
		if count.closes.Load() != 1 {
			t.Fatalf("close count=%d", count.closes.Load())
		}
		r, err := readLoadDirectReceipt(root)
		if err != nil {
			t.Fatal(err)
		}
		if r.Phase != "direct-handshake" || r.ElapsedNS != nil {
			t.Fatalf("construction receipt=%+v", r)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		mode    string
		failure bool
	}{
		"error: preface write never joins unstarted reader":    {mode: "preface-write"},
		"error: short preface original cause":                  {mode: "short-preface"},
		"error: EOF preface original cause":                    {mode: "eof-preface"},
		"error: malformed preface original cause":              {mode: "malformed-preface"},
		"error: settings failure joins started reader":         {mode: "settings-write"},
		"error: non-direct constructor keeps FailNow contract": {mode: "legacy-preface-write", failure: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestLoadDirectConstructionFailure$", "-test.v")
			cmd.Env = append(os.Environ(), childEnv+"="+tt.mode, "NETWORK_GATE_OUTPUT="+root)
			output, err := cmd.CombinedOutput()
			if writeErr := os.WriteFile(filepath.Join(root, "child.log"), output, 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
			if ctx.Err() != nil {
				t.Fatalf("unjoined child: %v\n%s", ctx.Err(), output)
			}
			if (err != nil) != tt.failure {
				t.Fatalf("constructor child: %v\n%s", err, output)
			}
			if tt.failure && !strings.Contains(string(output), "io: read/write on closed pipe") {
				t.Fatalf("non-direct error changed:\n%s", output)
			}
		})
	}
}

type loadPartialReader struct {
	data []byte
	err  error
}

func (r *loadPartialReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}

func TestLoadDirectPayloadAccounting(t *testing.T) {
	tests := map[string]struct {
		payload       []byte
		wantActual    int64
		wantValidated int64
		readErr       error
		padded        bool
	}{
		"success: complete frame":                          {payload: []byte("payload"), wantActual: 7, wantValidated: 7},
		"error: partial DATA and typed error in same read": {payload: []byte("part"), wantActual: 4, readErr: &net.OpError{Op: "read", Net: "tcp", Err: io.ErrUnexpectedEOF}},
		"success: padded DATA excludes padding":            {payload: []byte("data"), wantActual: 4, wantValidated: 4, padded: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var wire bytes.Buffer
			framer := http2.NewFramer(&wire, nil)
			if tt.padded {
				if err := framer.WriteDataPadded(3, true, tt.payload, []byte{0, 0, 0}); err != nil {
					t.Fatal(err)
				}
			} else if err := framer.WriteData(3, true, tt.payload); err != nil {
				t.Fatal(err)
			}
			data := wire.Bytes()
			if tt.readErr != nil {
				data[2] = 8
			}
			p := &loadHTTP2Peer{ctx: t.Context(), received: make(map[uint32]int64), failed: make(chan struct{}), done: make(chan struct{})}
			r := &loadPayloadReader{peer: p, source: &loadPartialReader{data: data, err: tt.readErr}, actual: make(map[uint32]int64), progress: make(map[uint32]int64)}
			p.payload = r
			reader := http2.NewFramer(nil, r)
			frame, err := reader.ReadFrame()
			if tt.readErr == nil {
				if err != nil {
					t.Fatal(err)
				}
				p.received[3] = int64(len(frame.(*http2.DataFrame).Data()))
			} else {
				if !errors.Is(err, tt.readErr) {
					t.Fatalf("read cause=%v", err)
				}
				p.recordFailure(err)
			}
			got := map[string]int64{"actual": r.actual[3], "validated": p.received[3]}
			want := map[string]int64{"actual": tt.wantActual, "validated": tt.wantValidated}
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Fatalf("DATA counters (-want +got):\n%s", diff)
			}
			if r.progress[3] <= 0 || r.wire != int64(len(data)) {
				t.Fatalf("wire/progress=%d/%d", r.wire, r.progress[3])
			}
			if tt.readErr != nil {
				s := &loadDirectTerminal{root: t.TempDir(), client: p, receipt: loadDirectReceipt{Phase: "direct-transfer", Stream: new(uint32(3)), ExpectedBytes: 8, Outcome: "failed"}}
				if err := s.publish(); err != nil {
					t.Fatal(err)
				}
				receipt, err := readLoadDirectReceipt(s.root)
				if err != nil {
					t.Fatal(err)
				}
				if receipt.Cause == nil || receipt.Cause.Type != "*net.OpError" || *receipt.ActualBytes != 4 || *receipt.ValidatedBytes != 0 {
					t.Fatalf("partial terminal=%+v", receipt)
				}
			}
		})
	}
}

func TestLoadDirectSnapshotRace(t *testing.T) {
	const childEnv = "MITMPROXY_GO_DIRECT_SNAPSHOT"
	if os.Getenv(childEnv) != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestLoadDirectSnapshotRace$", "-test.v")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		output, err := cmd.CombinedOutput()
		if ctx.Err() != nil || err != nil {
			t.Fatalf("snapshot subprocess: %v, watchdog=%v\n%s", err, ctx.Err(), output)
		}
		return
	}
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	client := makeLoadHTTP2Peer(t.Context(), a, nil, nil, true)
	defer client.close()
	c, d := net.Pipe()
	defer func() { _ = d.Close() }()
	origin := makeLoadHTTP2Peer(t.Context(), c, nil, nil, true)
	defer origin.close()
	first := &net.OpError{Op: "read", Net: "tcp", Err: io.ErrUnexpectedEOF}
	s := &loadDirectTerminal{root: t.TempDir(), client: client, origin: origin, receipt: loadDirectReceipt{Phase: "direct-transfer", Stream: new(uint32(3)), ExpectedBytes: 10, Outcome: "failed", ElapsedNS: new(int64(123))}}
	s.fail(first)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				client.mu.Lock()
				client.received[3]++
				client.payload.actual[3]++
				client.mu.Unlock()
				origin.recordFailure(io.ErrClosedPipe)
				s.fail(context.Canceled)
				_ = s.snapshot()
			}
		})
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot recursively locked a peer")
	}
	results := make(chan error, 8)
	for range 8 {
		workers.Go(func() { results <- s.publish() })
	}
	workers.Wait()
	published := 0
	for range 8 {
		if <-results == nil {
			published++
		}
	}
	if published != 1 {
		t.Fatalf("successful concurrent publications=%d", published)
	}
	r, err := readLoadDirectReceipt(s.root)
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(loadCause(first), r.Cause); diff != "" {
		t.Fatalf("first cause (-want +got):\n%s", diff)
	}
	if *r.ElapsedNS != 123 || *r.ActualBytes != 800 || *r.ValidatedBytes != 800 {
		t.Fatalf("snapshot=%+v", r)
	}
}

func TestLoadPeerLifecyclePreservation(t *testing.T) {
	t.Run("success: queued deadline completion and protocol precedence", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() { _ = b.Close() }()
		client := makeLoadHTTP2Peer(t.Context(), a, nil, nil, false)
		defer client.close()
		c, d := net.Pipe()
		defer func() { _ = d.Close() }()
		origin := makeLoadHTTP2Peer(t.Context(), c, nil, nil, false)
		defer origin.close()
		client.finished <- 3
		id, ok, err := awaitLoadDirect(t.Context(), client, origin, time.Nanosecond)
		if err != nil || !ok || id != 3 {
			t.Fatalf("queued completion=%d/%v/%v", id, ok, err)
		}
		failure := &net.OpError{Op: "read", Net: "tcp", Err: io.ErrUnexpectedEOF}
		client.recordFailure(failure)
		client.finished <- 3
		_, _, err = awaitLoadDirect(t.Context(), client, origin, time.Nanosecond)
		if !errors.Is(err, failure) {
			t.Fatalf("protocol precedence=%v", err)
		}
	})
	t.Run("success: non-direct proxy session remains unchanged", func(t *testing.T) {
		s := newLoadHTTP2Session(t, 128<<10, nil, 5*time.Minute)
		if s.client.payload != nil || s.origin.payload != nil {
			t.Fatal("proxy peer inherited direct accounting")
		}
		if err := s.request(3, "GET", "/small", true); err != nil {
			t.Fatal(err)
		}
		if got := await(t, s.client.finished); got != 3 {
			t.Fatalf("proxy completed stream=%d", got)
		}
		if got := s.client.bytes(3); got != 4<<20 {
			t.Fatalf("proxy bytes=%d", got)
		}
	})
	tests := map[string]struct{ diagnostic bool }{"success: unchanged non-direct peer": {}, "success: optional accounting peer": {diagnostic: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			ready := make(chan *loadHTTP2Peer, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					t.Error(err)
					return
				}
				ready <- newLoadHTTP2Peer(t, t.Context(), conn, false, nil, nil)
			}()
			conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			count := &loadCountedConn{Conn: conn}
			client := makeLoadHTTP2Peer(t.Context(), count, nil, nil, tt.diagnostic)
			t.Cleanup(client.close)
			if err := client.setup(true, 1<<20, 16<<20); err != nil {
				t.Fatal(err)
			}
			origin := await(t, ready)
			if err := client.headers(3, []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "localhost"}, {Name: ":path", Value: "/"}}, true); err != nil {
				t.Fatal(err)
			}
			if got := await(t, origin.finished); got != 3 {
				t.Fatalf("request stream=%d", got)
			}
			if err := loadResponse(origin, 3, 4096); err != nil {
				t.Fatal(err)
			}
			if got := await(t, client.finished); got != 3 {
				t.Fatalf("response stream=%d", got)
			}
			if got := client.bytes(3); got != 4096 {
				t.Fatalf("bytes=%d", got)
			}
			if (client.payload != nil) != tt.diagnostic {
				t.Fatal("non-direct caller inherited diagnostic reader")
			}
			client.close()
			client.close()
			if count.closes.Load() != 1 {
				t.Fatalf("close count=%d", count.closes.Load())
			}
			select {
			case <-client.done:
			default:
				t.Fatal("reader not joined")
			}
		})
	}
}
