// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package addontest provides an addon for testing hook dispatch.
package addontest

import (
	"context"
	"slices"
	"sync"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
)

// Call is one hook call a [Recorder] received.
type Call struct {
	// Hook is the mitmproxy name of the hook, for example "request".
	Hook string
	// Arg is the hook's argument: the flow, connection, hook data, log
	// entry, loader or set of option names; nil for running and done.
	Arg any
}

// Recorder is an addon that implements the handler of every hook and
// records each call in order. It is safe for concurrent use.
type Recorder struct {
	// AddonName is the name the recorder registers under; empty means
	// "recorder".
	AddonName string

	// Err, when set, is returned by every handler after the call is
	// recorded.
	Err error

	mu    sync.Mutex
	calls []Call
}

// Name implements [addon.Namer].
func (r *Recorder) Name() string {
	if r.AddonName == "" {
		return "recorder"
	}
	return r.AddonName
}

// Calls returns the calls recorded so far.
func (r *Recorder) Calls() []Call {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

// Hooks returns the names of the hooks recorded so far, in order.
func (r *Recorder) Hooks() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, len(r.calls))
	for i, c := range r.calls {
		names[i] = c.Hook
	}
	return names
}

// Reset forgets the recorded calls.
func (r *Recorder) Reset() {
	r.mu.Lock()
	r.calls = nil
	r.mu.Unlock()
}

func (r *Recorder) record(hook string, arg any) error {
	r.mu.Lock()
	r.calls = append(r.calls, Call{Hook: hook, Arg: arg})
	r.mu.Unlock()
	return r.Err
}

// Load records the load hook.
func (r *Recorder) Load(_ context.Context, l *addon.Loader) error {
	return r.record("load", l)
}

// Configure records the configure hook.
func (r *Recorder) Configure(_ context.Context, updated map[string]struct{}) error {
	return r.record("configure", updated)
}

// Running records the running hook.
func (r *Recorder) Running(context.Context) error {
	return r.record("running", nil)
}

// Done records the done hook.
func (r *Recorder) Done(context.Context) error {
	return r.record("done", nil)
}

// Update records the update hook.
func (r *Recorder) Update(_ context.Context, flows []flow.Flow) error {
	return r.record("update", flows)
}

// AddLog records the add_log hook.
func (r *Recorder) AddLog(_ context.Context, e addon.LogEntry) error {
	return r.record("add_log", e)
}

// NextLayer records the next_layer hook.
func (r *Recorder) NextLayer(_ context.Context, data *hookdata.NextLayer) error {
	return r.record("next_layer", data)
}

// ClientConnected records the client_connected hook.
func (r *Recorder) ClientConnected(_ context.Context, client *connection.Client) error {
	return r.record("client_connected", client)
}

// ClientDisconnected records the client_disconnected hook.
func (r *Recorder) ClientDisconnected(_ context.Context, client *connection.Client) error {
	return r.record("client_disconnected", client)
}

// ServerConnect records the server_connect hook.
func (r *Recorder) ServerConnect(_ context.Context, data *hookdata.ServerConnection) error {
	return r.record("server_connect", data)
}

// ServerConnected records the server_connected hook.
func (r *Recorder) ServerConnected(_ context.Context, data *hookdata.ServerConnection) error {
	return r.record("server_connected", data)
}

// ServerDisconnected records the server_disconnected hook.
func (r *Recorder) ServerDisconnected(_ context.Context, data *hookdata.ServerConnection) error {
	return r.record("server_disconnected", data)
}

// ServerConnectError records the server_connect_error hook.
func (r *Recorder) ServerConnectError(_ context.Context, data *hookdata.ServerConnection) error {
	return r.record("server_connect_error", data)
}

// Socks5Auth records the socks5_auth hook.
func (r *Recorder) Socks5Auth(_ context.Context, data *hookdata.Socks5Auth) error {
	return r.record("socks5_auth", data)
}

// RequestHeaders records the requestheaders hook.
func (r *Recorder) RequestHeaders(_ context.Context, f *flow.HTTPFlow) error {
	return r.record("requestheaders", f)
}

// Request records the request hook.
func (r *Recorder) Request(_ context.Context, f *flow.HTTPFlow) error {
	return r.record("request", f)
}

// ResponseHeaders records the responseheaders hook.
func (r *Recorder) ResponseHeaders(_ context.Context, f *flow.HTTPFlow) error {
	return r.record("responseheaders", f)
}

// Response records the response hook.
func (r *Recorder) Response(_ context.Context, f *flow.HTTPFlow) error {
	return r.record("response", f)
}

// Error records the error hook.
func (r *Recorder) Error(_ context.Context, f *flow.HTTPFlow) error {
	return r.record("error", f)
}

// HTTPConnect records the http_connect hook.
func (r *Recorder) HTTPConnect(_ context.Context, f *flow.HTTPFlow) error {
	return r.record("http_connect", f)
}

// HTTPConnectUpstream records the http_connect_upstream hook.
func (r *Recorder) HTTPConnectUpstream(_ context.Context, f *flow.HTTPFlow) error {
	return r.record("http_connect_upstream", f)
}

// HTTPConnected records the http_connected hook.
func (r *Recorder) HTTPConnected(_ context.Context, f *flow.HTTPFlow) error {
	return r.record("http_connected", f)
}

// HTTPConnectError records the http_connect_error hook.
func (r *Recorder) HTTPConnectError(_ context.Context, f *flow.HTTPFlow) error {
	return r.record("http_connect_error", f)
}

// WebSocketStart records the websocket_start hook.
func (r *Recorder) WebSocketStart(_ context.Context, f *flow.HTTPFlow) error {
	return r.record("websocket_start", f)
}

// WebSocketMessage records the websocket_message hook.
func (r *Recorder) WebSocketMessage(_ context.Context, f *flow.HTTPFlow) error {
	return r.record("websocket_message", f)
}

// WebSocketEnd records the websocket_end hook.
func (r *Recorder) WebSocketEnd(_ context.Context, f *flow.HTTPFlow) error {
	return r.record("websocket_end", f)
}

// TCPStart records the tcp_start hook.
func (r *Recorder) TCPStart(_ context.Context, f *flow.TCPFlow) error {
	return r.record("tcp_start", f)
}

// TCPMessage records the tcp_message hook.
func (r *Recorder) TCPMessage(_ context.Context, f *flow.TCPFlow) error {
	return r.record("tcp_message", f)
}

// TCPEnd records the tcp_end hook.
func (r *Recorder) TCPEnd(_ context.Context, f *flow.TCPFlow) error {
	return r.record("tcp_end", f)
}

// TCPError records the tcp_error hook.
func (r *Recorder) TCPError(_ context.Context, f *flow.TCPFlow) error {
	return r.record("tcp_error", f)
}

// UDPStart records the udp_start hook.
func (r *Recorder) UDPStart(_ context.Context, f *flow.UDPFlow) error {
	return r.record("udp_start", f)
}

// UDPMessage records the udp_message hook.
func (r *Recorder) UDPMessage(_ context.Context, f *flow.UDPFlow) error {
	return r.record("udp_message", f)
}

// UDPEnd records the udp_end hook.
func (r *Recorder) UDPEnd(_ context.Context, f *flow.UDPFlow) error {
	return r.record("udp_end", f)
}

// UDPError records the udp_error hook.
func (r *Recorder) UDPError(_ context.Context, f *flow.UDPFlow) error {
	return r.record("udp_error", f)
}

// DNSRequest records the dns_request hook.
func (r *Recorder) DNSRequest(_ context.Context, f *flow.DNSFlow) error {
	return r.record("dns_request", f)
}

// DNSResponse records the dns_response hook.
func (r *Recorder) DNSResponse(_ context.Context, f *flow.DNSFlow) error {
	return r.record("dns_response", f)
}

// DNSError records the dns_error hook.
func (r *Recorder) DNSError(_ context.Context, f *flow.DNSFlow) error {
	return r.record("dns_error", f)
}

// TLSClientHello records the tls_clienthello hook.
func (r *Recorder) TLSClientHello(_ context.Context, data *hookdata.ClientHello) error {
	return r.record("tls_clienthello", data)
}

// TLSStartClient records the tls_start_client hook.
func (r *Recorder) TLSStartClient(_ context.Context, data *hookdata.TLS) error {
	return r.record("tls_start_client", data)
}

// TLSStartServer records the tls_start_server hook.
func (r *Recorder) TLSStartServer(_ context.Context, data *hookdata.TLS) error {
	return r.record("tls_start_server", data)
}

// TLSEstablishedClient records the tls_established_client hook.
func (r *Recorder) TLSEstablishedClient(_ context.Context, data *hookdata.TLS) error {
	return r.record("tls_established_client", data)
}

// TLSEstablishedServer records the tls_established_server hook.
func (r *Recorder) TLSEstablishedServer(_ context.Context, data *hookdata.TLS) error {
	return r.record("tls_established_server", data)
}

// TLSFailedClient records the tls_failed_client hook.
func (r *Recorder) TLSFailedClient(_ context.Context, data *hookdata.TLS) error {
	return r.record("tls_failed_client", data)
}

// TLSFailedServer records the tls_failed_server hook.
func (r *Recorder) TLSFailedServer(_ context.Context, data *hookdata.TLS) error {
	return r.record("tls_failed_server", data)
}

// QUICStartClient records the quic_start_client hook.
func (r *Recorder) QUICStartClient(_ context.Context, data *hookdata.QUICTLS) error {
	return r.record("quic_start_client", data)
}

// QUICStartServer records the quic_start_server hook.
func (r *Recorder) QUICStartServer(_ context.Context, data *hookdata.QUICTLS) error {
	return r.record("quic_start_server", data)
}

// The recorder implements every hook handler.
var (
	_ addon.LoadHandler                 = (*Recorder)(nil)
	_ addon.ConfigureHandler            = (*Recorder)(nil)
	_ addon.RunningHandler              = (*Recorder)(nil)
	_ addon.DoneHandler                 = (*Recorder)(nil)
	_ addon.UpdateHandler               = (*Recorder)(nil)
	_ addon.AddLogHandler               = (*Recorder)(nil)
	_ addon.NextLayerHandler            = (*Recorder)(nil)
	_ addon.ClientConnectedHandler      = (*Recorder)(nil)
	_ addon.ClientDisconnectedHandler   = (*Recorder)(nil)
	_ addon.ServerConnectHandler        = (*Recorder)(nil)
	_ addon.ServerConnectedHandler      = (*Recorder)(nil)
	_ addon.ServerDisconnectedHandler   = (*Recorder)(nil)
	_ addon.ServerConnectErrorHandler   = (*Recorder)(nil)
	_ addon.Socks5AuthHandler           = (*Recorder)(nil)
	_ addon.RequestHeadersHandler       = (*Recorder)(nil)
	_ addon.RequestHandler              = (*Recorder)(nil)
	_ addon.ResponseHeadersHandler      = (*Recorder)(nil)
	_ addon.ResponseHandler             = (*Recorder)(nil)
	_ addon.ErrorHandler                = (*Recorder)(nil)
	_ addon.HTTPConnectHandler          = (*Recorder)(nil)
	_ addon.HTTPConnectUpstreamHandler  = (*Recorder)(nil)
	_ addon.HTTPConnectedHandler        = (*Recorder)(nil)
	_ addon.HTTPConnectErrorHandler     = (*Recorder)(nil)
	_ addon.WebSocketStartHandler       = (*Recorder)(nil)
	_ addon.WebSocketMessageHandler     = (*Recorder)(nil)
	_ addon.WebSocketEndHandler         = (*Recorder)(nil)
	_ addon.TCPStartHandler             = (*Recorder)(nil)
	_ addon.TCPMessageHandler           = (*Recorder)(nil)
	_ addon.TCPEndHandler               = (*Recorder)(nil)
	_ addon.TCPErrorHandler             = (*Recorder)(nil)
	_ addon.UDPStartHandler             = (*Recorder)(nil)
	_ addon.UDPMessageHandler           = (*Recorder)(nil)
	_ addon.UDPEndHandler               = (*Recorder)(nil)
	_ addon.UDPErrorHandler             = (*Recorder)(nil)
	_ addon.DNSRequestHandler           = (*Recorder)(nil)
	_ addon.DNSResponseHandler          = (*Recorder)(nil)
	_ addon.DNSErrorHandler             = (*Recorder)(nil)
	_ addon.TLSClientHelloHandler       = (*Recorder)(nil)
	_ addon.TLSStartClientHandler       = (*Recorder)(nil)
	_ addon.TLSStartServerHandler       = (*Recorder)(nil)
	_ addon.TLSEstablishedClientHandler = (*Recorder)(nil)
	_ addon.TLSEstablishedServerHandler = (*Recorder)(nil)
	_ addon.TLSFailedClientHandler      = (*Recorder)(nil)
	_ addon.TLSFailedServerHandler      = (*Recorder)(nil)
	_ addon.QUICStartClientHandler      = (*Recorder)(nil)
	_ addon.QUICStartServerHandler      = (*Recorder)(nil)
)
