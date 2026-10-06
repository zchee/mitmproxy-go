// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"runtime/pprof"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
	"github.com/zchee/mitmproxy-go/tlsparse"
)

type dtlsHeadClock struct {
	mu      sync.Mutex
	armed   chan time.Duration
	pending bool
	f       func()
}

func (*dtlsHeadClock) Now() time.Time { return time.Unix(100, 0) }

func (c *dtlsHeadClock) AfterFunc(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	c.pending, c.f = true, f
	c.mu.Unlock()
	c.armed <- d
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		pending := c.pending
		c.pending = false
		return pending
	}
}

func (c *dtlsHeadClock) expire() {
	c.mu.Lock()
	pending, f := c.pending, c.f
	c.pending = false
	c.mu.Unlock()
	if pending {
		f()
	}
}

type observedDTLSPackets struct {
	layer.PacketTransport
	reads chan struct{}
}

func (c *observedDTLSPackets) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketTransport.ReadFrom(p)
	if err == nil {
		c.reads <- struct{}{}
	}
	return n, addr, err
}

func dtlsHeadTransport(t *testing.T) (*observedDTLSPackets, func([]byte)) {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := packettransport.NewListener(t.Context(), socket)
	t.Cleanup(func() { _ = listener.Close() })
	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	send := func(p []byte) {
		t.Helper()
		if _, err := peer.WriteTo(p, listener.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	// Admission requires a first datagram; discard it to test a silent head.
	send(nil)
	conn, err := listener.Accept(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.ReadFrom(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	return &observedDTLSPackets{PacketTransport: conn, reads: make(chan struct{}, 1)}, send
}

func TestDTLSClientHelloHeadDeadline(t *testing.T) {
	// Upstream's complete DTLS ClientHello carrying SNI example.com.
	wire, err := hex.DecodeString("16fefd00000000000000000085010000790000000000000079fefd62bf0e0bf809df43e7669197be831919878b1a72c07a584d3c0a8ca6665878010000000cc02bc02fc00ac014c02cc03001000043000d0010000e0403050306030401050106010807ff01000100000a00080006001d00170018000b000201000017000000000010000e00000b6578616d706c652e636f6d")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		packets [][]byte
		expire  bool
		cancel  bool
		wantErr error
	}{
		"success: complete head cancels timer": {packets: [][]byte{wire}},
		"success: ordered packet bodies":       {packets: [][]byte{wire[:20], wire[20:]}},
		"error: silent head expires":           {expire: true, wantErr: os.ErrDeadlineExceeded},
		"error: trickled bytes cannot extend":  {packets: [][]byte{wire[:1], wire[1:2], wire[2:3]}, expire: true, wantErr: os.ErrDeadlineExceeded},
		"error: context wakes silent reader":   {cancel: true, wantErr: context.Canceled},
		"error: malformed head":                {packets: [][]byte{[]byte("GET /invalid!")}, wantErr: tlsparse.ErrMalformed},
		"error: bounded empty datagrams":       {packets: make([][]byte, layer.PacketQueueCapacity), wantErr: layer.ErrRecordSize},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if t.Failed() {
					_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
				}
			}()
			conn, send := dtlsHeadTransport(t)
			clock := &dtlsHeadClock{armed: make(chan time.Duration, 2)}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			type result struct {
				hello *tlsparse.ClientHello
				err   error
			}
			done := make(chan result, 1)
			go func() {
				hello, err := readDTLSClientHello(ctx, conn, clock)
				done <- result{hello, err}
			}()
			select {
			case d := <-clock.armed:
				if diff := cmp.Diff(layer.HeadReadTimeout, d); diff != "" {
					t.Fatal(diff)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("head reader did not arm injected timer")
			}
			for _, p := range tt.packets {
				send(p)
				select {
				case <-conn.reads:
				case <-time.After(10 * time.Second):
					t.Fatal("head reader did not consume datagram")
				}
			}
			if tt.expire {
				clock.expire()
			}
			if tt.cancel {
				cancel()
			}
			select {
			case got := <-done:
				if !errors.Is(got.err, tt.wantErr) {
					t.Fatalf("head error = %v, want %v", got.err, tt.wantErr)
				}
				if tt.wantErr == nil {
					if got.hello == nil {
						t.Fatal("complete head was not parsed")
					}
					if diff := cmp.Diff("example.com", got.hello.SNI()); diff != "" {
						t.Fatal(diff)
					}
				}
			case <-time.After(10 * time.Second):
				t.Fatal("head reader remained blocked")
			}
			select {
			case <-clock.armed:
				t.Fatal("trickled input rearmed the head timer")
			default:
			}
			// A late callback must not poison pion's subsequent packet reads.
			clock.expire()
			send([]byte("next packet"))
			if _, _, err := conn.PacketTransport.ReadFrom(make([]byte, 32)); err != nil {
				t.Fatalf("head reader left transport deadline active: %v", err)
			}
		})
	}
}
