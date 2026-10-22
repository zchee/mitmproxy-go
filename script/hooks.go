// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"fmt"
	"strings"

	"go.starlark.net/starlark"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
)

func (m *moduleAddon) flowHook(ctx context.Context, name string, f flow.Flow) error {
	if _, ok := m.members[name].(*concurrentValue); ok && m.concurrent != nil {
		return m.concurrentHook(ctx, name, f)
	}
	return m.call(ctx, name, func(i *invocation) (starlark.Tuple, error) { return starlark.Tuple{wrapFlow(i, f)}, nil })
}

func (m *moduleAddon) dataHook(ctx context.Context, name string, data any) error {
	return m.call(ctx, name, func(i *invocation) (starlark.Tuple, error) { return starlark.Tuple{wrapHookData(i, data)}, nil })
}

func (m *moduleAddon) Update(ctx context.Context, flows []flow.Flow) error {
	return m.call(ctx, "update", func(i *invocation) (starlark.Tuple, error) {
		value, err := new(conversion).value(i, flows, 0)
		return starlark.Tuple{value}, err
	})
}

func (m *logAddon) AddLog(ctx context.Context, e addon.LogEntry) error {
	// The manager logs a returned add_log error through the same log graph.
	// Its diagnostic is not another script event, avoiding cross-script loops.
	if strings.Contains(e.Msg, "Addon error: script add_log error: ") {
		return nil
	}
	if err := m.dataHook(ctx, "add_log", e); err != nil {
		return fmt.Errorf("script add_log error: %w", err)
	}
	return nil
}

func (m *moduleAddon) NextLayer(ctx context.Context, d *hookdata.NextLayer) error {
	return m.dataHook(ctx, "next_layer", d)
}

func (m *moduleAddon) ClientConnected(ctx context.Context, c *connection.Client) error {
	return m.dataHook(ctx, "client_connected", c)
}

func (m *moduleAddon) ClientDisconnected(ctx context.Context, c *connection.Client) error {
	return m.dataHook(ctx, "client_disconnected", c)
}

func (m *moduleAddon) ServerConnect(ctx context.Context, d *hookdata.ServerConnection) error {
	return m.dataHook(ctx, "server_connect", d)
}

func (m *moduleAddon) ServerConnected(ctx context.Context, d *hookdata.ServerConnection) error {
	return m.dataHook(ctx, "server_connected", d)
}

func (m *moduleAddon) ServerDisconnected(ctx context.Context, d *hookdata.ServerConnection) error {
	return m.dataHook(ctx, "server_disconnected", d)
}

func (m *moduleAddon) ServerConnectError(ctx context.Context, d *hookdata.ServerConnection) error {
	return m.dataHook(ctx, "server_connect_error", d)
}

func (m *moduleAddon) Socks5Auth(ctx context.Context, d *hookdata.Socks5Auth) error {
	return m.dataHook(ctx, "socks5_auth", d)
}

func (m *moduleAddon) RequestHeaders(ctx context.Context, f *flow.HTTPFlow) error {
	return m.flowHook(ctx, "requestheaders", f)
}

func (m *moduleAddon) Request(ctx context.Context, f *flow.HTTPFlow) error {
	return m.flowHook(ctx, "request", f)
}

func (m *moduleAddon) ResponseHeaders(ctx context.Context, f *flow.HTTPFlow) error {
	return m.flowHook(ctx, "responseheaders", f)
}

func (m *moduleAddon) Response(ctx context.Context, f *flow.HTTPFlow) error {
	return m.flowHook(ctx, "response", f)
}

func (m *moduleAddon) Error(ctx context.Context, f *flow.HTTPFlow) error {
	return m.flowHook(ctx, "error", f)
}

func (m *moduleAddon) HTTPConnect(ctx context.Context, f *flow.HTTPFlow) error {
	return m.flowHook(ctx, "http_connect", f)
}

func (m *moduleAddon) HTTPConnectUpstream(ctx context.Context, f *flow.HTTPFlow) error {
	return m.flowHook(ctx, "http_connect_upstream", f)
}

func (m *moduleAddon) HTTPConnected(ctx context.Context, f *flow.HTTPFlow) error {
	return m.flowHook(ctx, "http_connected", f)
}

func (m *moduleAddon) HTTPConnectError(ctx context.Context, f *flow.HTTPFlow) error {
	return m.flowHook(ctx, "http_connect_error", f)
}

func (m *moduleAddon) WebSocketStart(ctx context.Context, f *flow.HTTPFlow) error {
	return m.flowHook(ctx, "websocket_start", f)
}

func (m *moduleAddon) WebSocketMessage(ctx context.Context, f *flow.HTTPFlow) error {
	return m.flowHook(ctx, "websocket_message", f)
}

func (m *moduleAddon) WebSocketEnd(ctx context.Context, f *flow.HTTPFlow) error {
	return m.flowHook(ctx, "websocket_end", f)
}

func (m *moduleAddon) TCPStart(ctx context.Context, f *flow.TCPFlow) error {
	return m.flowHook(ctx, "tcp_start", f)
}

func (m *moduleAddon) TCPMessage(ctx context.Context, f *flow.TCPFlow) error {
	return m.flowHook(ctx, "tcp_message", f)
}

func (m *moduleAddon) TCPEnd(ctx context.Context, f *flow.TCPFlow) error {
	return m.flowHook(ctx, "tcp_end", f)
}

func (m *moduleAddon) TCPError(ctx context.Context, f *flow.TCPFlow) error {
	return m.flowHook(ctx, "tcp_error", f)
}

func (m *moduleAddon) UDPStart(ctx context.Context, f *flow.UDPFlow) error {
	return m.flowHook(ctx, "udp_start", f)
}

func (m *moduleAddon) UDPMessage(ctx context.Context, f *flow.UDPFlow) error {
	return m.flowHook(ctx, "udp_message", f)
}

func (m *moduleAddon) UDPEnd(ctx context.Context, f *flow.UDPFlow) error {
	return m.flowHook(ctx, "udp_end", f)
}

func (m *moduleAddon) UDPError(ctx context.Context, f *flow.UDPFlow) error {
	return m.flowHook(ctx, "udp_error", f)
}

func (m *moduleAddon) DNSRequest(ctx context.Context, f *flow.DNSFlow) error {
	return m.flowHook(ctx, "dns_request", f)
}

func (m *moduleAddon) DNSResponse(ctx context.Context, f *flow.DNSFlow) error {
	return m.flowHook(ctx, "dns_response", f)
}

func (m *moduleAddon) DNSError(ctx context.Context, f *flow.DNSFlow) error {
	return m.flowHook(ctx, "dns_error", f)
}

func (m *moduleAddon) TLSClientHello(ctx context.Context, d *hookdata.ClientHello) error {
	return m.dataHook(ctx, "tls_clienthello", d)
}

func (m *moduleAddon) TLSStartClient(ctx context.Context, d *hookdata.TLS) error {
	return m.dataHook(ctx, "tls_start_client", d)
}

func (m *moduleAddon) TLSStartServer(ctx context.Context, d *hookdata.TLS) error {
	return m.dataHook(ctx, "tls_start_server", d)
}

func (m *moduleAddon) TLSEstablishedClient(ctx context.Context, d *hookdata.TLS) error {
	return m.dataHook(ctx, "tls_established_client", d)
}

func (m *moduleAddon) TLSEstablishedServer(ctx context.Context, d *hookdata.TLS) error {
	return m.dataHook(ctx, "tls_established_server", d)
}

func (m *moduleAddon) TLSFailedClient(ctx context.Context, d *hookdata.TLS) error {
	return m.dataHook(ctx, "tls_failed_client", d)
}

func (m *moduleAddon) TLSFailedServer(ctx context.Context, d *hookdata.TLS) error {
	return m.dataHook(ctx, "tls_failed_server", d)
}

func (m *moduleAddon) QUICStartClient(ctx context.Context, d *hookdata.QUICTLS) error {
	return m.dataHook(ctx, "quic_start_client", d)
}

func (m *moduleAddon) QUICStartServer(ctx context.Context, d *hookdata.QUICTLS) error {
	return m.dataHook(ctx, "quic_start_server", d)
}
