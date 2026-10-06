// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// Upstream TestClientTLS.test_passthrough_from_clienthello, including both
// independent size caps and wire fragmentation beyond one recorder window.
func TestClientTLSRawReplay(t *testing.T) {
	tests := map[string]struct {
		recordSize                  int
		padding                     int
		open, wireCap, handshakeCap bool
	}{
		"closed server three records": {recordSize: 2000, padding: 5000},
		"open server small records":   {recordSize: 512, padding: 5000, open: true},
		"split handshake header":      {recordSize: 1, padding: 5000},
		"wire cap":                    {recordSize: 1, padding: 30000, wireCap: true},
		"handshake cap":               {recordSize: 512, handshakeCap: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			observer := &clientObserver{hello: func(data *hookdata.ClientHello) {
				data.IgnoreConnection = true
				if data.ClientHello.SNI() != "example.com" {
					t.Error("fragmented SNI not parsed")
				}
				if diff := gocmp.Diff([][]byte{[]byte("h2"), []byte("http/1.1")}, data.Context.Client.ALPNOffers); diff != "" {
					t.Error(diff)
				}
			}}
			s := newClientSession(t, observer)
			// TCP may coalesce small writes. Fragment reads deterministically,
			// retaining buffered bytes on the connection through raw handover.
			s.c.Client.StopRecording()
			fragmented := &fragmentReadConn{Conn: s.c.Client, reader: bufio.NewReader(s.c.Client)}
			s.c.Client = proxy.Record(fragmented)
			if tt.open {
				s.c.Server = proxy.Record(s.raw)
			}
			message := helloMessage(tt.padding)
			if tt.handshakeCap {
				message[1], message[2], message[3] = 1, 0, 0
			}
			wire := append(helloRecords(message, tt.recordSize), []byte("later records stay exact")...)
			written := make(chan error, 1)
			go func() {
				n, err := s.clientPeer.Write(wire)
				if err == nil && n != len(wire) {
					err = io.ErrShortWrite
				}
				if err == nil {
					err = s.clientPeer.CloseWrite()
				}
				written <- err
			}()
			// Model the next-layer selector consuming a prefix before handover.
			prefix := make([]byte, 3)
			if _, err := io.ReadFull(s.c.Client, prefix); err != nil {
				t.Fatal(err)
			}
			done := startClientLayer(t, s, &serverTLS{child: &clientTLS{}})
			got, err := io.ReadAll(s.peer)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wire, got) {
				t.Fatalf("wire replay differs: got %d bytes, want %d", len(got), len(wire))
			}
			if err := await(t, written); err != nil {
				t.Fatal(err)
			}
			if _, err := s.peer.Write([]byte("plaintext upstream response")); err != nil {
				t.Fatal(err)
			}
			if err := s.peer.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(s.clientPeer)
			if err != nil || string(reply) != "plaintext upstream response" {
				t.Fatalf("reverse after EOF = %q, %v", reply, err)
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
			if fragmented.reads != len(wire) {
				t.Fatalf("one-byte reads = %d, want %d", fragmented.reads, len(wire))
			}
			var want []string
			if !tt.wireCap && !tt.handshakeCap {
				want = []string{"tls_clienthello"}
			}
			if diff := gocmp.Diff(want, observer.events); diff != "" {
				t.Errorf("unexpected TLS/TCP hooks (-want +got):\n%s", diff)
			}
			if len(s.observed.events) != 0 || s.pool.setups != 0 {
				t.Fatalf("raw bypass started server TLS: events=%v setup=%d", s.observed.events, s.pool.setups)
			}
			if (tt.wireCap || tt.handshakeCap) && !strings.Contains(s.logs.String(), "forwarding raw TCP") {
				t.Errorf("cap fallback not logged: %q", s.logs.String())
			}
		})
	}
}

type fragmentReadConn struct {
	layer.Conn
	reader *bufio.Reader
	reads  int
}

func (c *fragmentReadConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p[:min(len(p), 1)])
	if n > 0 {
		c.reads++
	}
	return n, err
}

// Upstream TestClientTLS.test_server_required, with an additional upstream
// failure case that must still complete the client-side handshake.
func TestClientTLSServerFirst(t *testing.T) {
	tests := map[string]struct{ open, fail bool }{
		"closed server": {}, "open server": {open: true}, "failed server": {fail: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			config, peerConfig := tlsConfigs(t)
			originConfig, upstreamConfig := tlsConfigs(t)
			config.NextProtos, peerConfig.NextProtos = []string{"quux"}, []string{"quux"}
			originConfig.NextProtos, upstreamConfig.NextProtos = []string{"quux"}, []string{"quux"}
			if tt.fail {
				upstreamConfig.ServerName = "wrong.host"
			}
			var events []string
			observer := &clientObserver{
				config: config,
				hello: func(data *hookdata.ClientHello) {
					events = append(events, "hello")
					if !data.Context.Server.TLS {
						t.Error("server intent not set before clienthello")
					}
					data.EstablishServerTLSFirst = true
				},
				check: func(event string, data *hookdata.TLS) {
					events = append(events, event)
					if event == "tls_start_client" && !tt.fail && (!data.Context.Server.TLSEstablished() || string(data.Context.Server.ALPN) != "quux") {
						t.Error("client config hook preceded server result")
					}
				},
			}
			s := newClientSession(t, observer)
			s.observed.config = upstreamConfig
			s.observed.check = func(event string, _ *hookdata.TLS) { events = append(events, event) }
			if tt.open {
				s.c.Server = proxy.Record(s.raw)
			}
			originDone := make(chan error, 1)
			go func() {
				err := tls.Server(s.peer, originConfig).HandshakeContext(t.Context())
				if tt.fail && err != nil {
					err = nil
				}
				originDone <- err
			}()
			done := startClientLayer(t, s, &serverTLS{child: &clientTLS{child: lowerEcho()}})
			peer := tls.Client(s.clientPeer, peerConfig)
			if err := peer.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err := peer.Write([]byte("PING")); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 4)
			if _, err := io.ReadFull(peer, reply); err != nil || string(reply) != "ping" {
				t.Fatalf("reply=%q, %v", reply, err)
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
			if err := await(t, originDone); err != nil {
				t.Fatal(err)
			}
			serverResult := "tls_established_server"
			if tt.fail {
				serverResult = "tls_failed_server"
			}
			want := []string{"hello", "tls_start_server", serverResult, "tls_start_client", "tls_established_client"}
			if diff := gocmp.Diff(want, events); diff != "" {
				t.Error(diff)
			}
			if s.pool.setups != 1 {
				t.Errorf("server handshakes=%d, want 1", s.pool.setups)
			}
			if tt.fail && !strings.Contains(s.logs.String(), "Unable to establish TLS connection with server") {
				t.Errorf("nonfatal upstream failure not logged: %s", s.logs.String())
			}
		})
	}
}

// fragmentHelloConn splits the first real crypto/tls ClientHello across
// wire records without changing any transcript bytes.
type fragmentHelloConn struct {
	layer.Conn
	split int
	first bool
}

func (c *fragmentHelloConn) Write(p []byte) (int, error) {
	if c.first {
		return c.Conn.Write(p)
	}
	c.first = true
	wire := make([]byte, 0, len(p))
	for remaining := p; len(remaining) > 0; {
		if len(remaining) < 5 {
			return 0, io.ErrUnexpectedEOF
		}
		n := int(binary.BigEndian.Uint16(remaining[3:5]))
		if len(remaining) < n+5 {
			return 0, io.ErrUnexpectedEOF
		}
		payload := remaining[5 : n+5]
		for len(payload) > 0 {
			m := min(len(payload), c.split)
			wire = append(wire, remaining[:3]...)
			wire = binary.BigEndian.AppendUint16(wire, uint16(m))
			wire = append(wire, payload[:m]...)
			payload = payload[m:]
		}
		remaining = remaining[n+5:]
	}
	for _, b := range wire {
		if _, err := c.Conn.Write([]byte{b}); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func TestClientTLSFragmentedHandshake(t *testing.T) {
	tests := map[string]struct{ size int }{"512 byte records": {512}, "split header": {1}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			config, peerConfig := tlsConfigs(t)
			observer := &clientObserver{config: config}
			s := newClientSession(t, observer)
			done := startClientLayer(t, s, &clientTLS{child: lowerEcho()})
			peer := tls.Client(&fragmentHelloConn{Conn: s.clientPeer, split: tt.size}, peerConfig)
			if err := peer.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err := peer.Write([]byte("PING")); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 4)
			if _, err := io.ReadFull(peer, reply); err != nil || string(reply) != "ping" {
				t.Fatalf("reply=%q, %v", reply, err)
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}
