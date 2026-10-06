// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	dtls "github.com/pion/dtls/v3"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type dtlsObserver struct {
	startClient func(*hookdata.TLS)
	startServer func(*hookdata.TLS)
	hello       func(*hookdata.ClientHello)
	check       func(string, *hookdata.TLS)
	events      []string
}

func (*dtlsObserver) Name() string { return "dtls_test_observer" }

func (o *dtlsObserver) TLSClientHello(_ context.Context, d *hookdata.ClientHello) error {
	o.events = append(o.events, "tls_clienthello")
	if o.hello != nil {
		o.hello(d)
	}
	return nil
}

func (o *dtlsObserver) TLSStartClient(_ context.Context, d *hookdata.TLS) error {
	if o.startClient != nil {
		o.startClient(d)
	}
	return o.handle("tls_start_client", d)
}

func (o *dtlsObserver) TLSStartServer(_ context.Context, d *hookdata.TLS) error {
	if o.startServer != nil {
		o.startServer(d)
	}
	return o.handle("tls_start_server", d)
}

func (o *dtlsObserver) TLSEstablishedClient(_ context.Context, d *hookdata.TLS) error {
	return o.handle("tls_established_client", d)
}

func (o *dtlsObserver) TLSEstablishedServer(_ context.Context, d *hookdata.TLS) error {
	return o.handle("tls_established_server", d)
}

func (o *dtlsObserver) TLSFailedClient(_ context.Context, d *hookdata.TLS) error {
	return o.handle("tls_failed_client", d)
}

func (o *dtlsObserver) TLSFailedServer(_ context.Context, d *hookdata.TLS) error {
	return o.handle("tls_failed_server", d)
}

func (o *dtlsObserver) handle(event string, d *hookdata.TLS) error {
	o.events = append(o.events, event)
	if o.check != nil {
		o.check(event, d)
	}
	return nil
}

func TestDTLSServerConfigurationAndTransportFailure(t *testing.T) {
	tests := map[string]struct {
		configure func(*hookdata.TLS)
		openErr   error
		missing   bool
		closeRaw  bool
		wantErr   error
	}{
		"error: nil DTLS config": {wantErr: hookdata.ErrTLSConfig},
		"error: TLS config on DTLS": {
			configure: func(d *hookdata.TLS) { d.Config = &tls.Config{} }, wantErr: hookdata.ErrTLSConfig,
		},
		"error: both transports configured": {
			configure: func(d *hookdata.TLS) {
				d.Config = &tls.Config{}
				d.DTLSConfig = &dtls.Config{} //nolint:staticcheck // The mutable hook surface is intentional.
			}, wantErr: hookdata.ErrTLSConfig,
		},
		"error: transport closed before handshake": {openErr: net.ErrClosed, wantErr: net.ErrClosed},
		"error: transport fails during handshake": {
			configure: func(d *hookdata.TLS) {
				d.DTLSConfig = &dtls.Config{InsecureSkipVerify: true} //nolint:staticcheck // Frozen hook config override.
			}, closeRaw: true, wantErr: net.ErrClosed,
		},
		"error: no packet transport": {missing: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newServerSession(t, &tlsObserver{})
			observer := &dtlsObserver{startServer: tt.configure}
			observer.check = func(event string, d *hookdata.TLS) {
				if !d.IsDTLS || !d.IsServer() {
					t.Errorf("%s: wrong DTLS target", event)
				}
				if d.Conn.TLSEstablished() || d.Conn.TimestampTLSSetup != nil {
					t.Errorf("%s: failed handshake published established state", event)
				}
			}
			if err := s.manager.Add(t.Context(), observer); err != nil {
				t.Fatal(err)
			}
			raw, _ := dtlsHeadTransport(t)
			server := s.c.Data.Server
			if err := s.manager.Do(t.Context(), func(context.Context) error {
				server.TransportProtocol = connection.UDP
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if tt.closeRaw {
				_ = raw.Close()
			}
			state := &dtlsServerState{c: s.c, openRaw: func(context.Context, *connection.Server) (layer.PacketTransport, *connection.Server, error) {
				if tt.openErr != nil {
					return nil, nil, tt.openErr
				}
				if tt.missing {
					return nil, server, nil
				}
				return raw, server, nil
			}}
			defer func() {
				for _, session := range state.sessions {
					_ = session.Close()
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			_, _, err := state.open(ctx, server)
			if err == nil || tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("open error = %v, want %v", err, tt.wantErr)
			}
			var wantEvents []string
			if tt.openErr == nil && !tt.missing {
				wantEvents = []string{"tls_start_server", "tls_failed_server"}
			}
			if diff := cmp.Diff(wantEvents, observer.events); diff != "" {
				t.Fatal(diff)
			}
			metadata := s.server(t)
			if metadata.TLSEstablished() || metadata.TimestampTLSSetup != nil || metadata.Cipher != nil {
				t.Fatal("failed DTLS handshake published established metadata")
			}
		})
	}
}
