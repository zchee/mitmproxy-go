// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build h2load

package httplayer

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

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
