// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build h2load

package httplayer

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
)

func TestLoadNetemTimeoutDiagnostics(t *testing.T) {
	const childEnv = "MITMPROXY_GO_NETEM_TIMEOUT_DIAGNOSTIC"
	if mode := os.Getenv(childEnv); mode != "" {
		client, origin := new(loadHTTP2Peer), new(loadHTTP2Peer)
		switch mode {
		case "client-failure":
			client.failure = errors.New("stream reset after deadline liveness check")
		case "origin-failure":
			origin.failure = errors.New("GOAWAY after deadline liveness check")
		case "live":
		default:
			t.Fatalf("unknown diagnostic fixture %q", mode)
		}
		logLoadNetemTimeout(t, client, origin, `NETEM {"phase":"measured-transfer-timeout","outcome":"measured-transfer-timeout"}`)
		t.Log("timeout receipt returned")
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
		"success: live peers publish timeout":                         {mode: "live"},
		"error: client failure supersedes timeout before publication": {mode: "client-failure", failure: true},
		"error: origin failure supersedes timeout before publication": {mode: "origin-failure", failure: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// A subprocess observes FailNow without failing the surrounding diagnostic contract.
			cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestLoadNetemTimeoutDiagnostics$", "-test.v")
			cmd.Env = append(os.Environ(), childEnv+"="+tt.mode)
			output, err := cmd.CombinedOutput()
			if err != nil {
				if _, ok := errors.AsType[*exec.ExitError](err); !ok {
					t.Fatalf("diagnostic child execution failed: %v\n%s", err, output)
				}
			}
			want := map[string]bool{"failure": tt.failure, "protocol": tt.failure, "timeout": !tt.failure, "returned": !tt.failure}
			got := map[string]bool{
				"failure":  err != nil,
				"protocol": strings.Contains(string(output), `"outcome":"protocol-failure"`),
				"timeout":  strings.Contains(string(output), `"outcome":"measured-transfer-timeout"`),
				"returned": strings.Contains(string(output), "timeout receipt returned"),
			}
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Fatalf("timeout diagnostic (-want +got):\n%s\nchild output:\n%s", diff, output)
			}
		})
	}
}

func TestLoadNetemPeerDiagnostics(t *testing.T) {
	tests := map[string]struct {
		trigger func(*loadHTTP2Peer, *loadHTTP2Peer) error
	}{
		"error: stream reset remains visible on a live connection": {
			trigger: func(_, origin *loadHTTP2Peer) error {
				return origin.write(func(f *http2.Framer) error { return f.WriteRSTStream(3, http2.ErrCodeCancel) })
			},
		},
		"error: GOAWAY remains visible on a live connection": {
			trigger: func(_, origin *loadHTTP2Peer) error {
				return origin.write(func(f *http2.Framer) error { return f.WriteGoAway(3, http2.ErrCodeProtocol, nil) })
			},
		},
		"error: malformed frame records the reader failure": {
			trigger: func(_, origin *loadHTTP2Peer) error {
				return origin.write(func(f *http2.Framer) error { return f.WriteRawFrame(http2.FrameData, 0, 0, []byte("invalid")) })
			},
		},
		"error: connection closure records the reader failure": {
			trigger: func(_, origin *loadHTTP2Peer) error { return origin.conn.Close() },
		},
		"error: failed write records terminal diagnostics": {
			trigger: func(client, _ *loadHTTP2Peer) error {
				if err := client.conn.Close(); err != nil {
					return err
				}
				if err := client.write(func(f *http2.Framer) error { return f.WritePing(false, [8]byte{}) }); err == nil {
					return errors.New("write to closed connection succeeded")
				}
				return nil
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
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
			client := newLoadHTTP2Peer(t, t.Context(), conn, true, nil, nil)
			origin := await(t, ready)
			if err := tt.trigger(client, origin); err != nil {
				t.Fatal(err)
			}
			select {
			case <-client.failed:
			case <-time.After(5 * time.Second):
				t.Fatal("peer failure diagnostic was not published")
			}
			client.mu.Lock()
			failure := client.failure
			client.mu.Unlock()
			if failure == nil {
				t.Fatal("failure notification has no diagnostic")
			}
		})
	}
}
