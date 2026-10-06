// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestDTLSClientLayerHeadDeadline(t *testing.T) {
	wire, err := hex.DecodeString("16fefd00000000000000000085010000790000000000000079fefd62bf0e0bf809df43e7669197be831919878b1a72c07a584d3c0a8ca6665878010000000cc02bc02fc00ac014c02cc03001000043000d0010000e0403050306030401050106010807ff01000100000a00080006001d00170018000b000201000017000000000010000e00000b6578616d706c652e636f6d")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		packets [][]byte
		expire  bool
		cancel  bool
		wantErr error
		events  []string
	}{
		"error: silent client expires through layer": {
			expire: true, wantErr: os.ErrDeadlineExceeded,
			events: []string{"tls_failed_client"},
		},
		"error: trickled client cannot extend head timer": {
			packets: [][]byte{wire[:1], wire[1:2], wire[2:3]},
			expire:  true, wantErr: os.ErrDeadlineExceeded,
			events: []string{"tls_failed_client"},
		},
		"error: client cancellation wakes layer without failed hook": {
			cancel: true, wantErr: context.Canceled,
		},
		"error: complete head stops timer before invalid configuration": {
			packets: [][]byte{wire}, wantErr: hookdata.ErrTLSConfig,
			events: []string{"tls_clienthello", "tls_start_client", "tls_failed_client"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if t.Failed() {
					_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
				}
			}()
			raw, send := dtlsHeadTransport(t)
			s := newServerSession(t, &tlsObserver{})
			observer := &dtlsObserver{check: func(event string, d *hookdata.TLS) {
				if !d.IsDTLS || !d.IsClient() {
					t.Errorf("%s has the wrong DTLS target", event)
				}
				if d.Conn.TLSEstablished() || d.Conn.TimestampTLSSetup != nil {
					t.Errorf("%s published established state before handshake", event)
				}
				if event == "tls_failed_client" && d.Conn.Error == nil {
					t.Error("failed hook ran before publishing the connection error")
				}
			}}
			if err := s.manager.Add(t.Context(), observer); err != nil {
				t.Fatal(err)
			}
			if err := s.c.Do(t.Context(), func(context.Context) error {
				s.c.Data.Client.TransportProtocol = connection.UDP
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			clock := &dtlsHeadClock{armed: make(chan time.Duration, 2)}
			s.c.ClientPackets, s.c.RecordPackets, s.c.Clock = proxy.RecordPackets(raw), proxy.RecordPackets, clock
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			client, err := layer.Build(ctx, s.c, hookdata.LayerStack{{Kind: hookdata.LayerClientDTLS}})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				done <- client.Run(ctx, s.c)
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-stopped:
				case <-time.After(10 * time.Second):
					t.Error("client DTLS layer did not stop")
					_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
				}
			})
			select {
			case d := <-clock.armed:
				if diff := cmp.Diff(layer.HeadReadTimeout, d); diff != "" {
					t.Fatal(diff)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("client DTLS layer did not arm the injected head timer")
			}
			for _, packet := range tt.packets {
				send(packet)
				select {
				case <-raw.reads:
				case <-time.After(10 * time.Second):
					t.Fatal("client DTLS layer did not consume the datagram")
				}
			}
			if tt.expire {
				clock.expire()
			}
			if tt.cancel {
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("client layer error = %v, want %v", err, tt.wantErr)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("client DTLS layer remained blocked")
			}
			select {
			case <-clock.armed:
				t.Fatal("client DTLS layer rearmed the head timer")
			default:
			}
			if err := s.c.Do(t.Context(), func(context.Context) error {
				if diff := cmp.Diff(tt.events, observer.events); diff != "" {
					t.Error(diff)
				}
				if s.c.Data.Client.TLSEstablished() || s.c.Data.Client.TimestampTLSSetup != nil || s.c.Data.Client.Cipher != nil {
					t.Error("failed client layer left established metadata")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			clock.expire()
			send([]byte("next packet"))
			if _, _, err := raw.PacketTransport.ReadFrom(make([]byte, 32)); err != nil {
				t.Fatalf("client DTLS layer left the head deadline active: %v", err)
			}
		})
	}
}
