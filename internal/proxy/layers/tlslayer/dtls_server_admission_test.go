// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestDTLSServerInitialPacketAdmission(t *testing.T) {
	tests := map[string]struct {
		packet []byte
		drop   bool
	}{
		"success: discard DTLS 1.2 alert":          {packet: []byte{21, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 1, 0, 2, 1, 0}, drop: true},
		"success: discard DTLS 1.0 alert":          {packet: []byte{21, 0xfe, 0xfe}, drop: true},
		"success: discard change cipher spec":      {packet: []byte{20, 0xfe, 0xfd}, drop: true},
		"success: discard application data":        {packet: []byte{23, 0xfe, 0xfd}, drop: true},
		"success: preserve handshake record":       {packet: []byte{22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1}},
		"success: preserve ordinary UDP":           {packet: []byte("plain UDP")},
		"success: preserve empty UDP":              {},
		"success: preserve truncated prefix":       {packet: []byte{21, 0xfe}},
		"success: preserve unrelated version":      {packet: []byte{21, 3, 3}},
		"success: preserve unrelated content type": {packet: []byte{42, 0xfe, 0xfd}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newServerSession(t, &tlsObserver{})
			packets, send := dtlsHeadTransport(t)
			send(tt.packet)
			s.c.ClientPackets = proxy.RecordPackets(packets)
			s.c.RecordPackets = proxy.RecordPackets
			opens := 0
			s.c.OpenPackets = func(context.Context, *connection.Server) (layer.PacketTransport, *connection.Server, error) {
				opens++
				return nil, nil, net.ErrClosed
			}
			if err := s.c.Do(t.Context(), func(context.Context) error {
				s.c.Data.Server.TransportProtocol = connection.UDP
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			childCalls := 0
			stack := &serverDTLS{child: innerLayer{kind: "test-dtls-admission", run: func(ctx context.Context, c *layer.Context) error {
				childCalls++
				c.ClientPackets.StopRecording()
				buf := make([]byte, 256)
				n, _, err := c.ClientPackets.ReadFrom(buf)
				if err != nil {
					return err
				}
				if diff := cmp.Diff(string(tt.packet), string(buf[:n])); diff != "" {
					t.Errorf("first datagram changed: %s", diff)
				}
				var server *connection.Server
				if err := c.Do(ctx, func(context.Context) error {
					server = c.Data.Server
					return nil
				}); err != nil {
					return err
				}
				_, _, err = c.OpenPackets(ctx, server)
				return err
			}}}
			err := stack.Run(t.Context(), s.c)
			if tt.drop {
				if err != nil || opens != 0 || childCalls != 0 {
					t.Fatalf("stale record: err=%v origin attempts=%d child calls=%d; want clean discard without origin or child", err, opens, childCalls)
				}
			} else if !errors.Is(err, net.ErrClosed) || opens != 1 || childCalls != 1 {
				t.Fatalf("accepted datagram: err=%v origin attempts=%d child calls=%d; want preserved packet and one origin attempt", err, opens, childCalls)
			}
		})
	}
}
