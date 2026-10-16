// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package packettest

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func queuedPair(t *testing.T, ctx context.Context) (*Transport, *Transport) {
	t.Helper()
	a, b, err := NewPair(ctx, netip.MustParseAddrPort("127.0.0.1:20001"), netip.MustParseAddrPort("127.0.0.1:20002"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestQueuedPacketTransport(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	tests := map[string]struct{ run func(*testing.T) }{
		"FIFO clone empty and truncation": {run: func(t *testing.T) {
			a, b := queuedPair(t, t.Context())
			borrowed := []byte("first")
			for _, data := range [][]byte{borrowed, {}, []byte("truncate"), []byte("last")} {
				if n, err := a.WriteTo(data, a.RemoteAddr()); err != nil || n != len(data) {
					t.Fatalf("enqueue bytes=%d/%d error=%v", n, len(data), err)
				}
			}
			copy(borrowed, "other")
			for _, want := range [][]byte{[]byte("first"), {}, []byte("trunc"), []byte("last")} {
				data := make([]byte, 5)
				n, peer, err := b.ReadFrom(data)
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(want, data[:n]); diff != "" {
					t.Fatalf("datagram (-want +got):\n%s", diff)
				}
				if peer.String() != a.LocalAddr().String() {
					t.Fatalf("source=%v, want %v", peer, a.LocalAddr())
				}
			}
			if _, err := b.WriteTo([]byte("reply"), nil); err != nil {
				t.Fatal(err)
			}
			var data [5]byte
			if n, _, err := a.ReadFrom(data[:]); err != nil || string(data[:n]) != "reply" {
				t.Fatalf("reverse datagram=%q error=%v", data[:n], err)
			}
		}},
		"fixed immutable identity": {run: func(t *testing.T) {
			a, b := queuedPair(t, t.Context())
			local, peer := a.LocalAddr().String(), a.RemoteAddr().String()
			a.LocalAddr().(*net.UDPAddr).Port++
			a.RemoteAddr().(*net.UDPAddr).IP[0]++
			if a.LocalAddr().String() != local || a.RemoteAddr().String() != peer {
				t.Fatal("caller mutated fixed tuple identity")
			}
			if _, err := a.WriteTo(nil, a.LocalAddr()); err == nil {
				t.Fatal("different destination accepted")
			}
			if b.count != 0 {
				t.Fatal("rejected packet reached peer")
			}
		}},
		"ring wraps without reordering": {run: func(t *testing.T) {
			a, b := queuedPair(t, t.Context())
			for i := range 3 * layer.PacketQueueCapacity {
				if _, err := a.WriteTo([]byte{byte(i)}, nil); err != nil {
					t.Fatal(err)
				}
				var data [1]byte
				if n, _, err := b.ReadFrom(data[:]); err != nil || n != 1 || data[0] != byte(i) {
					t.Fatalf("packet=%v bytes=%d error=%v, want %d", data, n, err, i)
				}
			}
		}},
		"invalid identities": {run: func(t *testing.T) {
			valid := netip.MustParseAddrPort("127.0.0.1:20001")
			for _, other := range []netip.AddrPort{{}, netip.MustParseAddrPort("127.0.0.1:0"), valid} {
				if a, b, err := NewPair(t.Context(), valid, other); err == nil || a != nil || b != nil {
					t.Fatalf("invalid peer=%v accepted: %v %v %v", other, a, b, err)
				}
			}
		}},
		"cancellation and concurrent Close join": {run: func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancelCause(t.Context())
				a, b := queuedPair(t, ctx)
				cause := errors.New("fixture canceled")
				result := make(chan error, 1)
				go func() { _, _, err := b.ReadFrom(nil); result <- err }()
				synctest.Wait()
				cancel(cause)
				if err := <-result; !errors.Is(err, net.ErrClosed) || !errors.Is(err, cause) {
					t.Fatalf("read cancellation=%v, want closed and original cause", err)
				}
				var closers sync.WaitGroup
				for range 8 {
					closers.Go(func() { _ = a.Close(); _ = b.Close() })
				}
				closers.Wait()
				if !errors.Is(context.Cause(a.Context()), cause) || !errors.Is(context.Cause(b.Context()), cause) {
					t.Fatal("transport lost parent cancellation cause")
				}
			})
		}},
		"Close releases queue and blocked reader": {run: func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := queuedPair(t, t.Context())
				if _, err := a.WriteTo([]byte("queued"), nil); err != nil {
					t.Fatal(err)
				}
				result := make(chan error, 1)
				go func() { _, _, err := a.ReadFrom(nil); result <- err }()
				synctest.Wait()
				_ = a.Close()
				if err := <-result; !errors.Is(err, net.ErrClosed) {
					t.Fatalf("closed reader=%v", err)
				}
				_ = b.Close()
				if b.count != 0 || b.bytes != 0 {
					t.Fatal("Close retained queued input")
				}
				if _, err := b.WriteTo(nil, nil); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("write after Close=%v", err)
				}
			})
		}},
		"deadline changes wake reads and can be cleared": {run: func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := queuedPair(t, t.Context())
				result := make(chan error, 1)
				go func() { _, _, err := b.ReadFrom(nil); result <- err }()
				synctest.Wait()
				if err := b.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				if err := <-result; !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("read deadline=%v", err)
				}
				if err := b.SetDeadline(time.Unix(1, 0)); err != nil {
					t.Fatal(err)
				}
				if _, err := b.WriteTo(nil, nil); !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("write deadline=%v", err)
				}
				if err := b.SetDeadline(time.Time{}); err != nil {
					t.Fatal(err)
				}
				if err := a.SetWriteDeadline(time.Time{}); err != nil {
					t.Fatal(err)
				}
				if _, err := a.WriteTo([]byte("after deadline"), nil); err != nil {
					t.Fatal(err)
				}
				var data [32]byte
				if n, _, err := b.ReadFrom(data[:]); err != nil || string(data[:n]) != "after deadline" {
					t.Fatalf("recovered read=%q error=%v", data[:n], err)
				}
			})
		}},
	}
	for name, test := range tests {
		t.Run(name, test.run)
	}
	bounds := map[string]struct{ size, accepted int }{
		"packet count includes empty datagrams": {accepted: layer.PacketQueueCapacity},
		"aggregate byte limit":                  {size: layer.MaxUDPPacketBytes, accepted: layer.PacketQueueBytes / layer.MaxUDPPacketBytes},
		"maximum datagram size":                 {size: layer.MaxUDPPacketBytes + 1},
	}
	for name, test := range bounds {
		t.Run(name, func(t *testing.T) {
			a, b := queuedPair(t, t.Context())
			data := bytes.Repeat([]byte("x"), test.size)
			for range test.accepted {
				if _, err := a.WriteTo(data, nil); err != nil {
					t.Fatalf("valid enqueue failed: %v", err)
				}
			}
			if n, err := a.WriteTo(data, nil); n != 0 || !errors.Is(err, layer.ErrPacketOverflow) {
				t.Fatalf("overflow bytes=%d error=%v", n, err)
			}
			if _, _, err := b.ReadFrom(nil); !errors.Is(err, layer.ErrPacketOverflow) || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("receiver overflow cause=%v", err)
			}
			if b.count != 0 || b.bytes != 0 {
				t.Fatal("overflow retained queued payloads")
			}
		})
	}
}
