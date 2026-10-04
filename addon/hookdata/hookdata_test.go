// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package hookdata_test

import (
	"testing"

	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// TestConnSide checks that IsClient and IsServer tell the two sides apart,
// as mitmproxy addons do with data.conn == data.context.client, and that a
// handler's change through Conn reaches the connection itself.
func TestConnSide(t *testing.T) {
	client := connection.NewClient(connection.Address{Host: "127.0.0.1", Port: 51234}, connection.Address{Host: "127.0.0.1", Port: 8080}, 1)
	ctx := &hookdata.Context{Client: client, Server: &connection.Server{}}
	other := connection.NewClient(connection.Address{Host: "127.0.0.1", Port: 1}, connection.Address{Host: "127.0.0.1", Port: 2}, 1)

	type sides interface {
		IsClient() bool
		IsServer() bool
	}
	tests := map[string]struct {
		data       sides
		conn       func() *connection.Connection // where a write through Conn must land
		wantClient bool
		wantServer bool
	}{
		"success: TLS client side": {
			data:       &hookdata.TLS{Conn: &ctx.Client.Connection, Context: ctx},
			conn:       func() *connection.Connection { return &ctx.Client.Connection },
			wantClient: true,
		},
		"success: TLS server side": {
			data:       &hookdata.TLS{Conn: &ctx.Server.Connection, Context: ctx},
			conn:       func() *connection.Connection { return &ctx.Server.Connection },
			wantServer: true,
		},
		"success: QUIC client side": {
			data:       &hookdata.QUICTLS{Conn: &ctx.Client.Connection, Context: ctx},
			conn:       func() *connection.Connection { return &ctx.Client.Connection },
			wantClient: true,
		},
		"success: QUIC server side": {
			data:       &hookdata.QUICTLS{Conn: &ctx.Server.Connection, Context: ctx},
			conn:       func() *connection.Connection { return &ctx.Server.Connection },
			wantServer: true,
		},
		"error: connection of another client": {
			data: &hookdata.TLS{Conn: &other.Connection, Context: ctx},
		},
		"error: no context": {
			data: &hookdata.TLS{Conn: &ctx.Client.Connection},
		},
		"error: no connection": {
			data: &hookdata.QUICTLS{Context: ctx},
		},
		"error: context without a server": {
			data: &hookdata.TLS{Conn: &ctx.Server.Connection, Context: &hookdata.Context{Client: client}},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tt.data.IsClient(); got != tt.wantClient {
				t.Errorf("IsClient() = %v, want %v", got, tt.wantClient)
			}
			if got := tt.data.IsServer(); got != tt.wantServer {
				t.Errorf("IsServer() = %v, want %v", got, tt.wantServer)
			}
			if tt.conn == nil {
				return
			}
			var conn *connection.Connection
			switch d := tt.data.(type) {
			case *hookdata.TLS:
				conn = d.Conn
			case *hookdata.QUICTLS:
				conn = d.Conn
			}
			sni := "example.com"
			conn.SNI = &sni
			if got := tt.conn().SNI; got == nil || *got != sni {
				t.Errorf("SNI set through Conn did not reach the connection: got %v", got)
			}
			tt.conn().SNI = nil
		})
	}
}

func TestVerifyModeString(t *testing.T) {
	tests := map[string]struct {
		mode hookdata.VerifyMode
		want string
	}{
		"success: none":     {mode: hookdata.VerifyNone, want: "CERT_NONE"},
		"success: optional": {mode: hookdata.VerifyOptional, want: "CERT_OPTIONAL"},
		"success: required": {mode: hookdata.VerifyRequired, want: "CERT_REQUIRED"},
		"error: unknown":    {mode: hookdata.VerifyMode(7), want: "VerifyMode(7)"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tt.mode.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
