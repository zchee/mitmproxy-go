// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func BenchmarkNetstackTCP(b *testing.B) {
	for _, size := range []int{1024, 1048576} {
		b.Run(fmt.Sprintf("bytes=%d", size), func(b *testing.B) {
			ctx, cancel := context.WithCancel(b.Context())
			defer cancel()
			target, err := New(ctx)
			if err != nil {
				b.Fatal(err)
			}
			peer, link, err := newGVisor(nil)
			if err != nil {
				_ = target.Close()
				b.Fatal(err)
			}
			if err := peer.AddProtocolAddress(nicID, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 0, 0, 1}).WithPrefix()}, stack.AddressProperties{}); err != nil {
				b.Fatal(err)
			}
			var workers sync.WaitGroup
			workers.Go(func() {
				for {
					packet := link.ReadContext(ctx)
					if packet == nil {
						return
					}
					view := packet.ToView()
					err := target.Inject(view.AsSlice(), nil)
					view.Release()
					packet.DecRef()
					if err != nil {
						return
					}
				}
			})
			workers.Go(func() {
				for {
					select {
					case <-ctx.Done():
						return
					case wire, ok := <-target.Outbound():
						if !ok {
							return
						}
						packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(wire)})
						link.InjectInbound(ipv4.ProtocolNumber, packet)
						packet.DecRef()
					}
				}
			})
			defer func() {
				cancel()
				_ = target.Close()
				link.Close()
				peer.Destroy()
				workers.Wait()
			}()
			client, err := gonet.DialContextTCP(ctx, peer, tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}), Port: 31337}, ipv4.ProtocolNumber)
			if err != nil {
				b.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			var stream *Stream
			select {
			case stream = <-target.TCPConns():
			case <-ctx.Done():
				b.Fatal(ctx.Err())
			}
			workers.Go(func() { _, _ = io.Copy(stream, stream) })
			payload := bytes.Repeat([]byte("netstack"), size/8)
			want := sha256.Sum256(payload)
			commands := make(chan struct{})
			written := make(chan error, 1)
			workers.Go(func() {
				for {
					select {
					case <-ctx.Done():
						return
					case <-commands:
						_, err := io.Copy(client, bytes.NewReader(payload))
						written <- err
					}
				}
			})
			digest := sha256.New()
			readBuffer := make([]byte, 32<<10)
			sum := make([]byte, 0, sha256.Size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				commands <- struct{}{}
				digest.Reset()
				if _, err := io.CopyBuffer(digest, io.LimitReader(client, int64(size)), readBuffer); err != nil {
					b.Fatal(err)
				}
				if err := <-written; err != nil {
					b.Fatal(err)
				}
				if !bytes.Equal(digest.Sum(sum[:0]), want[:]) {
					b.Fatal("TCP echo checksum mismatch")
				}
			}
		})
	}
}
