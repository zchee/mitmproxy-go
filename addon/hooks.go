// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package addon

import (
	"context"
	"fmt"
	"reflect"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
)

// Hook is an event dispatched to addons. Each hook is a struct type of this
// package named after the mitmproxy hook it ports, such as [ConfigureHook]
// for configure; its fields are the hook's arguments.
//
// An addon receives a hook by implementing the hook's single-method handler
// interface, such as [ConfigureHandler]. A handler returns nil, an error to
// have it logged, or an error wrapping [ErrAddonHalt] to stop the hook from
// reaching the addons after it.
type Hook interface {
	// Name returns the mitmproxy name of the hook, for example
	// "configure".
	Name() string

	// invoke calls the hook's handler method on a, when a implements it.
	invoke(ctx context.Context, a any) (handled bool, err error)
}

// LoadHook is mitmproxy's load hook: it runs once when an addon is
// registered, before the addon receives any other hook. The addon adds its
// options and commands through the [Loader].
//
// Only [Manager.Register] and [Manager.Add] fire it, each with a Loader of
// the addon's own; a Loader cannot be built outside this package. A
// LoadHook without a Loader is refused with an error wrapping
// [ErrAddonManager] before any handler runs: [Manager.InvokeSync] returns
// that error, and [Manager.Trigger] logs it as a handler error.
type LoadHook struct{ Loader *Loader }

// ConfigureHook is mitmproxy's configure hook: it runs after options
// change, with the names of the options that changed, and at startup with
// every option.
type ConfigureHook struct{ Updated map[string]struct{} }

// RunningHook is mitmproxy's running hook: it runs once the proxy is fully
// up, when all addons are loaded and all options are set.
type RunningHook struct{}

// DoneHook is mitmproxy's done hook: it runs when an addon is removed or
// the proxy shuts down, and is the last hook the addon receives.
type DoneHook struct{}

// UpdateHook is mitmproxy's update hook: one or more flows have been
// changed, usually by another addon. [Manager.Hook] fires it after every
// flow hook, with that hook's flow.
type UpdateHook struct{ Flows []flow.Flow }

// AddLogHook is mitmproxy's deprecated add_log hook: it runs for every log
// entry. A handler must not log, or each entry it logs feeds the hook again.
type AddLogHook struct{ Entry LogEntry }

// NextLayerHook is mitmproxy's next_layer hook: it runs when the proxy
// must decide which protocol layer handles a connection next.
type NextLayerHook struct{ Data *hookdata.NextLayer }

// ClientConnectedHook is mitmproxy's client_connected hook: a client has
// connected to the proxy. A handler may set the client's Error to refuse
// the connection.
type ClientConnectedHook struct{ Client *connection.Client }

// ClientDisconnectedHook is mitmproxy's client_disconnected hook: a client
// connection has been closed, by either side.
type ClientDisconnectedHook struct{ Client *connection.Client }

// ServerConnectHook is mitmproxy's server_connect hook: the proxy is about
// to connect to a server. A handler may set the server's Error to prevent
// the connection.
type ServerConnectHook struct{ Data *hookdata.ServerConnection }

// ServerConnectedHook is mitmproxy's server_connected hook: the proxy has
// connected to a server.
type ServerConnectedHook struct{ Data *hookdata.ServerConnection }

// ServerDisconnectedHook is mitmproxy's server_disconnected hook: a server
// connection has been closed, by either side.
type ServerDisconnectedHook struct{ Data *hookdata.ServerConnection }

// ServerConnectErrorHook is mitmproxy's server_connect_error hook: the
// proxy could not connect to a server.
type ServerConnectErrorHook struct{ Data *hookdata.ServerConnection }

// Socks5AuthHook is mitmproxy's socks5_auth hook: a SOCKS5 client sent
// credentials, which a handler accepts by setting Data.Valid.
type Socks5AuthHook struct{ Data *hookdata.Socks5Auth }

// RequestHeadersHook is mitmproxy's requestheaders hook: HTTP request headers
// were successfully read. At this point, the body is empty.
type RequestHeadersHook struct{ Flow *flow.HTTPFlow }

// RequestHook is mitmproxy's request hook: the full HTTP request has been
// read.
type RequestHook struct{ Flow *flow.HTTPFlow }

// ResponseHeadersHook is mitmproxy's responseheaders hook: HTTP response
// headers were successfully read. At this point, the body is empty.
type ResponseHeadersHook struct{ Flow *flow.HTTPFlow }

// ResponseHook is mitmproxy's response hook: the full HTTP response has been
// read.
type ResponseHook struct{ Flow *flow.HTTPFlow }

// ErrorHook is mitmproxy's error hook: an HTTP error has occurred, such as an
// invalid server response or an interrupted connection. This is distinct from
// a valid server HTTP error response, which is simply a response with an HTTP
// error code. Every flow receives either error or response, not both.
type ErrorHook struct{ Flow *flow.HTTPFlow }

// HTTPConnectHook is mitmproxy's http_connect hook: an HTTP CONNECT request
// was received. A handler may set the flow's response to answer the request
// itself; a non-2xx response makes the proxy close the connection.
type HTTPConnectHook struct{ Flow *flow.HTTPFlow }

// HTTPConnectUpstreamHook is mitmproxy's http_connect_upstream hook: an HTTP
// CONNECT request is about to be sent to an upstream proxy. A handler may add
// headers to it, for example for authentication.
type HTTPConnectUpstreamHook struct{ Flow *flow.HTTPFlow }

// HTTPConnectedHook is mitmproxy's http_connected hook: an HTTP CONNECT tunnel
// was established.
type HTTPConnectedHook struct{ Flow *flow.HTTPFlow }

// HTTPConnectErrorHook is mitmproxy's http_connect_error hook: an HTTP CONNECT
// tunnel failed, for example because the upstream proxy refused it or the
// server could not be reached.
type HTTPConnectErrorHook struct{ Flow *flow.HTTPFlow }

// WebSocketStartHook is mitmproxy's websocket_start hook: a WebSocket
// connection has commenced.
type WebSocketStartHook struct{ Flow *flow.HTTPFlow }

// WebSocketMessageHook is mitmproxy's websocket_message hook: a WebSocket
// message was received from the client or the server; it is the last message
// in the flow's WebSocket messages. A handler may change it or drop it.
type WebSocketMessageHook struct{ Flow *flow.HTTPFlow }

// WebSocketEndHook is mitmproxy's websocket_end hook: a WebSocket connection
// has ended. The flow's WebSocket data holds the close code and reason.
type WebSocketEndHook struct{ Flow *flow.HTTPFlow }

// TCPStartHook is mitmproxy's tcp_start hook: a TCP connection has started.
type TCPStartHook struct{ Flow *flow.TCPFlow }

// TCPMessageHook is mitmproxy's tcp_message hook: a TCP connection has
// received a message; it is the last message in the flow. A handler may change
// it.
type TCPMessageHook struct{ Flow *flow.TCPFlow }

// TCPEndHook is mitmproxy's tcp_end hook: a TCP connection has ended.
type TCPEndHook struct{ Flow *flow.TCPFlow }

// TCPErrorHook is mitmproxy's tcp_error hook: a TCP error has occurred. Every
// TCP flow receives either tcp_error or tcp_end, not both.
type TCPErrorHook struct{ Flow *flow.TCPFlow }

// UDPStartHook is mitmproxy's udp_start hook: a UDP connection has started.
type UDPStartHook struct{ Flow *flow.UDPFlow }

// UDPMessageHook is mitmproxy's udp_message hook: a UDP connection has
// received a message; it is the last message in the flow. A handler may change
// it.
type UDPMessageHook struct{ Flow *flow.UDPFlow }

// UDPEndHook is mitmproxy's udp_end hook: a UDP connection has ended.
type UDPEndHook struct{ Flow *flow.UDPFlow }

// UDPErrorHook is mitmproxy's udp_error hook: a UDP error has occurred. Every
// UDP flow receives either udp_error or udp_end, not both.
type UDPErrorHook struct{ Flow *flow.UDPFlow }

// DNSRequestHook is mitmproxy's dns_request hook: a DNS query has been
// received.
type DNSRequestHook struct{ Flow *flow.DNSFlow }

// DNSResponseHook is mitmproxy's dns_response hook: a DNS response has been
// received or set.
type DNSResponseHook struct{ Flow *flow.DNSFlow }

// DNSErrorHook is mitmproxy's dns_error hook: a DNS error has occurred.
type DNSErrorHook struct{ Flow *flow.DNSFlow }

// TLSClientHelloHook is mitmproxy's tls_clienthello hook: a client's TLS
// ClientHello has been received.
type TLSClientHelloHook struct{ Data *hookdata.ClientHello }

// TLSStartClientHook is mitmproxy's tls_start_client hook: TLS between the
// client and the proxy is about to start. A handler sets Data.Config.
type TLSStartClientHook struct{ Data *hookdata.TLS }

// TLSStartServerHook is mitmproxy's tls_start_server hook: TLS between the
// proxy and the server is about to start. A handler sets Data.Config.
type TLSStartServerHook struct{ Data *hookdata.TLS }

// TLSEstablishedClientHook is mitmproxy's tls_established_client hook: TLS
// with the client has been established.
type TLSEstablishedClientHook struct{ Data *hookdata.TLS }

// TLSEstablishedServerHook is mitmproxy's tls_established_server hook: TLS
// with the server has been established.
type TLSEstablishedServerHook struct{ Data *hookdata.TLS }

// TLSFailedClientHook is mitmproxy's tls_failed_client hook: the TLS
// handshake with the client failed.
type TLSFailedClientHook struct{ Data *hookdata.TLS }

// TLSFailedServerHook is mitmproxy's tls_failed_server hook: the TLS
// handshake with the server failed.
type TLSFailedServerHook struct{ Data *hookdata.TLS }

// QUICStartClientHook is mitmproxy's quic_start_client hook: TLS with the
// client over QUIC is about to start. A handler sets Data.Settings.
type QUICStartClientHook struct{ Data *hookdata.QUICTLS }

// QUICStartServerHook is mitmproxy's quic_start_server hook: TLS with the
// server over QUIC is about to start. A handler sets Data.Settings.
type QUICStartServerHook struct{ Data *hookdata.QUICTLS }

// LoadHandler receives the load hook.
type LoadHandler interface {
	Load(ctx context.Context, l *Loader) error
}

// ConfigureHandler receives the configure hook.
type ConfigureHandler interface {
	Configure(ctx context.Context, updated map[string]struct{}) error
}

// RunningHandler receives the running hook.
type RunningHandler interface {
	Running(ctx context.Context) error
}

// DoneHandler receives the done hook.
type DoneHandler interface {
	Done(ctx context.Context) error
}

// UpdateHandler receives the update hook.
type UpdateHandler interface {
	Update(ctx context.Context, flows []flow.Flow) error
}

// AddLogHandler receives the add_log hook. The hook is deprecated, as in
// mitmproxy; install a [log/slog.Handler] instead.
type AddLogHandler interface {
	AddLog(ctx context.Context, e LogEntry) error
}

// NextLayerHandler receives the next_layer hook.
type NextLayerHandler interface {
	NextLayer(ctx context.Context, data *hookdata.NextLayer) error
}

// ClientConnectedHandler receives the client_connected hook.
type ClientConnectedHandler interface {
	ClientConnected(ctx context.Context, client *connection.Client) error
}

// ClientDisconnectedHandler receives the client_disconnected hook.
type ClientDisconnectedHandler interface {
	ClientDisconnected(ctx context.Context, client *connection.Client) error
}

// ServerConnectHandler receives the server_connect hook.
type ServerConnectHandler interface {
	ServerConnect(ctx context.Context, data *hookdata.ServerConnection) error
}

// ServerConnectedHandler receives the server_connected hook.
type ServerConnectedHandler interface {
	ServerConnected(ctx context.Context, data *hookdata.ServerConnection) error
}

// ServerDisconnectedHandler receives the server_disconnected hook.
type ServerDisconnectedHandler interface {
	ServerDisconnected(ctx context.Context, data *hookdata.ServerConnection) error
}

// ServerConnectErrorHandler receives the server_connect_error hook.
type ServerConnectErrorHandler interface {
	ServerConnectError(ctx context.Context, data *hookdata.ServerConnection) error
}

// Socks5AuthHandler receives the socks5_auth hook.
type Socks5AuthHandler interface {
	Socks5Auth(ctx context.Context, data *hookdata.Socks5Auth) error
}

// RequestHeadersHandler receives the requestheaders hook.
type RequestHeadersHandler interface {
	RequestHeaders(ctx context.Context, f *flow.HTTPFlow) error
}

// RequestHandler receives the request hook.
type RequestHandler interface {
	Request(ctx context.Context, f *flow.HTTPFlow) error
}

// ResponseHeadersHandler receives the responseheaders hook.
type ResponseHeadersHandler interface {
	ResponseHeaders(ctx context.Context, f *flow.HTTPFlow) error
}

// ResponseHandler receives the response hook.
type ResponseHandler interface {
	Response(ctx context.Context, f *flow.HTTPFlow) error
}

// ErrorHandler receives the error hook.
type ErrorHandler interface {
	Error(ctx context.Context, f *flow.HTTPFlow) error
}

// HTTPConnectHandler receives the http_connect hook.
type HTTPConnectHandler interface {
	HTTPConnect(ctx context.Context, f *flow.HTTPFlow) error
}

// HTTPConnectUpstreamHandler receives the http_connect_upstream hook.
type HTTPConnectUpstreamHandler interface {
	HTTPConnectUpstream(ctx context.Context, f *flow.HTTPFlow) error
}

// HTTPConnectedHandler receives the http_connected hook.
type HTTPConnectedHandler interface {
	HTTPConnected(ctx context.Context, f *flow.HTTPFlow) error
}

// HTTPConnectErrorHandler receives the http_connect_error hook.
type HTTPConnectErrorHandler interface {
	HTTPConnectError(ctx context.Context, f *flow.HTTPFlow) error
}

// WebSocketStartHandler receives the websocket_start hook.
type WebSocketStartHandler interface {
	WebSocketStart(ctx context.Context, f *flow.HTTPFlow) error
}

// WebSocketMessageHandler receives the websocket_message hook.
type WebSocketMessageHandler interface {
	WebSocketMessage(ctx context.Context, f *flow.HTTPFlow) error
}

// WebSocketEndHandler receives the websocket_end hook.
type WebSocketEndHandler interface {
	WebSocketEnd(ctx context.Context, f *flow.HTTPFlow) error
}

// TCPStartHandler receives the tcp_start hook.
type TCPStartHandler interface {
	TCPStart(ctx context.Context, f *flow.TCPFlow) error
}

// TCPMessageHandler receives the tcp_message hook.
type TCPMessageHandler interface {
	TCPMessage(ctx context.Context, f *flow.TCPFlow) error
}

// TCPEndHandler receives the tcp_end hook.
type TCPEndHandler interface {
	TCPEnd(ctx context.Context, f *flow.TCPFlow) error
}

// TCPErrorHandler receives the tcp_error hook.
type TCPErrorHandler interface {
	TCPError(ctx context.Context, f *flow.TCPFlow) error
}

// UDPStartHandler receives the udp_start hook.
type UDPStartHandler interface {
	UDPStart(ctx context.Context, f *flow.UDPFlow) error
}

// UDPMessageHandler receives the udp_message hook.
type UDPMessageHandler interface {
	UDPMessage(ctx context.Context, f *flow.UDPFlow) error
}

// UDPEndHandler receives the udp_end hook.
type UDPEndHandler interface {
	UDPEnd(ctx context.Context, f *flow.UDPFlow) error
}

// UDPErrorHandler receives the udp_error hook.
type UDPErrorHandler interface {
	UDPError(ctx context.Context, f *flow.UDPFlow) error
}

// DNSRequestHandler receives the dns_request hook.
type DNSRequestHandler interface {
	DNSRequest(ctx context.Context, f *flow.DNSFlow) error
}

// DNSResponseHandler receives the dns_response hook.
type DNSResponseHandler interface {
	DNSResponse(ctx context.Context, f *flow.DNSFlow) error
}

// DNSErrorHandler receives the dns_error hook.
type DNSErrorHandler interface {
	DNSError(ctx context.Context, f *flow.DNSFlow) error
}

// TLSClientHelloHandler receives the tls_clienthello hook.
type TLSClientHelloHandler interface {
	TLSClientHello(ctx context.Context, data *hookdata.ClientHello) error
}

// TLSStartClientHandler receives the tls_start_client hook.
type TLSStartClientHandler interface {
	TLSStartClient(ctx context.Context, data *hookdata.TLS) error
}

// TLSStartServerHandler receives the tls_start_server hook.
type TLSStartServerHandler interface {
	TLSStartServer(ctx context.Context, data *hookdata.TLS) error
}

// TLSEstablishedClientHandler receives the tls_established_client hook.
type TLSEstablishedClientHandler interface {
	TLSEstablishedClient(ctx context.Context, data *hookdata.TLS) error
}

// TLSEstablishedServerHandler receives the tls_established_server hook.
type TLSEstablishedServerHandler interface {
	TLSEstablishedServer(ctx context.Context, data *hookdata.TLS) error
}

// TLSFailedClientHandler receives the tls_failed_client hook.
type TLSFailedClientHandler interface {
	TLSFailedClient(ctx context.Context, data *hookdata.TLS) error
}

// TLSFailedServerHandler receives the tls_failed_server hook.
type TLSFailedServerHandler interface {
	TLSFailedServer(ctx context.Context, data *hookdata.TLS) error
}

// QUICStartClientHandler receives the quic_start_client hook.
type QUICStartClientHandler interface {
	QUICStartClient(ctx context.Context, data *hookdata.QUICTLS) error
}

// QUICStartServerHandler receives the quic_start_server hook.
type QUICStartServerHandler interface {
	QUICStartServer(ctx context.Context, data *hookdata.QUICTLS) error
}

// Name implements [Hook].
func (LoadHook) Name() string { return "load" }

// Name implements [Hook].
func (ConfigureHook) Name() string { return "configure" }

// Name implements [Hook].
func (RunningHook) Name() string { return "running" }

// Name implements [Hook].
func (DoneHook) Name() string { return "done" }

// Name implements [Hook].
func (UpdateHook) Name() string { return "update" }

// Name implements [Hook].
func (AddLogHook) Name() string { return "add_log" }

// Name implements [Hook].
func (NextLayerHook) Name() string { return "next_layer" }

// Name implements [Hook].
func (ClientConnectedHook) Name() string { return "client_connected" }

// Name implements [Hook].
func (ClientDisconnectedHook) Name() string { return "client_disconnected" }

// Name implements [Hook].
func (ServerConnectHook) Name() string { return "server_connect" }

// Name implements [Hook].
func (ServerConnectedHook) Name() string { return "server_connected" }

// Name implements [Hook].
func (ServerDisconnectedHook) Name() string { return "server_disconnected" }

// Name implements [Hook].
func (ServerConnectErrorHook) Name() string { return "server_connect_error" }

// Name implements [Hook].
func (Socks5AuthHook) Name() string { return "socks5_auth" }

// Name implements [Hook].
func (RequestHeadersHook) Name() string { return "requestheaders" }

// Name implements [Hook].
func (RequestHook) Name() string { return "request" }

// Name implements [Hook].
func (ResponseHeadersHook) Name() string { return "responseheaders" }

// Name implements [Hook].
func (ResponseHook) Name() string { return "response" }

// Name implements [Hook].
func (ErrorHook) Name() string { return "error" }

// Name implements [Hook].
func (HTTPConnectHook) Name() string { return "http_connect" }

// Name implements [Hook].
func (HTTPConnectUpstreamHook) Name() string { return "http_connect_upstream" }

// Name implements [Hook].
func (HTTPConnectedHook) Name() string { return "http_connected" }

// Name implements [Hook].
func (HTTPConnectErrorHook) Name() string { return "http_connect_error" }

// Name implements [Hook].
func (WebSocketStartHook) Name() string { return "websocket_start" }

// Name implements [Hook].
func (WebSocketMessageHook) Name() string { return "websocket_message" }

// Name implements [Hook].
func (WebSocketEndHook) Name() string { return "websocket_end" }

// Name implements [Hook].
func (TCPStartHook) Name() string { return "tcp_start" }

// Name implements [Hook].
func (TCPMessageHook) Name() string { return "tcp_message" }

// Name implements [Hook].
func (TCPEndHook) Name() string { return "tcp_end" }

// Name implements [Hook].
func (TCPErrorHook) Name() string { return "tcp_error" }

// Name implements [Hook].
func (UDPStartHook) Name() string { return "udp_start" }

// Name implements [Hook].
func (UDPMessageHook) Name() string { return "udp_message" }

// Name implements [Hook].
func (UDPEndHook) Name() string { return "udp_end" }

// Name implements [Hook].
func (UDPErrorHook) Name() string { return "udp_error" }

// Name implements [Hook].
func (DNSRequestHook) Name() string { return "dns_request" }

// Name implements [Hook].
func (DNSResponseHook) Name() string { return "dns_response" }

// Name implements [Hook].
func (DNSErrorHook) Name() string { return "dns_error" }

// Name implements [Hook].
func (TLSClientHelloHook) Name() string { return "tls_clienthello" }

// Name implements [Hook].
func (TLSStartClientHook) Name() string { return "tls_start_client" }

// Name implements [Hook].
func (TLSStartServerHook) Name() string { return "tls_start_server" }

// Name implements [Hook].
func (TLSEstablishedClientHook) Name() string { return "tls_established_client" }

// Name implements [Hook].
func (TLSEstablishedServerHook) Name() string { return "tls_established_server" }

// Name implements [Hook].
func (TLSFailedClientHook) Name() string { return "tls_failed_client" }

// Name implements [Hook].
func (TLSFailedServerHook) Name() string { return "tls_failed_server" }

// Name implements [Hook].
func (QUICStartClientHook) Name() string { return "quic_start_client" }

// Name implements [Hook].
func (QUICStartServerHook) Name() string { return "quic_start_server" }

func (h LoadHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(LoadHandler)
	if !ok {
		return false, nil
	}
	if h.Loader == nil {
		return true, fmt.Errorf("%w: the load hook has no Loader; only Register and Add fire it", ErrAddonManager)
	}
	return true, x.Load(ctx, h.Loader)
}

func (h ConfigureHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(ConfigureHandler)
	if !ok {
		return false, nil
	}
	return true, x.Configure(ctx, h.Updated)
}

func (RunningHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(RunningHandler)
	if !ok {
		return false, nil
	}
	return true, x.Running(ctx)
}

func (DoneHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(DoneHandler)
	if !ok {
		return false, nil
	}
	return true, x.Done(ctx)
}

func (h UpdateHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(UpdateHandler)
	if !ok {
		return false, nil
	}
	return true, x.Update(ctx, h.Flows)
}

func (h AddLogHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(AddLogHandler)
	if !ok {
		return false, nil
	}
	return true, x.AddLog(ctx, h.Entry)
}

func (h NextLayerHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(NextLayerHandler)
	if !ok {
		return false, nil
	}
	return true, x.NextLayer(ctx, h.Data)
}

func (h ClientConnectedHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(ClientConnectedHandler)
	if !ok {
		return false, nil
	}
	return true, x.ClientConnected(ctx, h.Client)
}

func (h ClientDisconnectedHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(ClientDisconnectedHandler)
	if !ok {
		return false, nil
	}
	return true, x.ClientDisconnected(ctx, h.Client)
}

func (h ServerConnectHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(ServerConnectHandler)
	if !ok {
		return false, nil
	}
	return true, x.ServerConnect(ctx, h.Data)
}

func (h ServerConnectedHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(ServerConnectedHandler)
	if !ok {
		return false, nil
	}
	return true, x.ServerConnected(ctx, h.Data)
}

func (h ServerDisconnectedHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(ServerDisconnectedHandler)
	if !ok {
		return false, nil
	}
	return true, x.ServerDisconnected(ctx, h.Data)
}

func (h ServerConnectErrorHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(ServerConnectErrorHandler)
	if !ok {
		return false, nil
	}
	return true, x.ServerConnectError(ctx, h.Data)
}

func (h Socks5AuthHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(Socks5AuthHandler)
	if !ok {
		return false, nil
	}
	return true, x.Socks5Auth(ctx, h.Data)
}

func (h RequestHeadersHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(RequestHeadersHandler)
	if !ok {
		return false, nil
	}
	return true, x.RequestHeaders(ctx, h.Flow)
}

func (h RequestHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(RequestHandler)
	if !ok {
		return false, nil
	}
	return true, x.Request(ctx, h.Flow)
}

func (h ResponseHeadersHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(ResponseHeadersHandler)
	if !ok {
		return false, nil
	}
	return true, x.ResponseHeaders(ctx, h.Flow)
}

func (h ResponseHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(ResponseHandler)
	if !ok {
		return false, nil
	}
	return true, x.Response(ctx, h.Flow)
}

func (h ErrorHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(ErrorHandler)
	if !ok {
		return false, nil
	}
	return true, x.Error(ctx, h.Flow)
}

func (h HTTPConnectHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(HTTPConnectHandler)
	if !ok {
		return false, nil
	}
	return true, x.HTTPConnect(ctx, h.Flow)
}

func (h HTTPConnectUpstreamHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(HTTPConnectUpstreamHandler)
	if !ok {
		return false, nil
	}
	return true, x.HTTPConnectUpstream(ctx, h.Flow)
}

func (h HTTPConnectedHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(HTTPConnectedHandler)
	if !ok {
		return false, nil
	}
	return true, x.HTTPConnected(ctx, h.Flow)
}

func (h HTTPConnectErrorHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(HTTPConnectErrorHandler)
	if !ok {
		return false, nil
	}
	return true, x.HTTPConnectError(ctx, h.Flow)
}

func (h WebSocketStartHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(WebSocketStartHandler)
	if !ok {
		return false, nil
	}
	return true, x.WebSocketStart(ctx, h.Flow)
}

func (h WebSocketMessageHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(WebSocketMessageHandler)
	if !ok {
		return false, nil
	}
	return true, x.WebSocketMessage(ctx, h.Flow)
}

func (h WebSocketEndHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(WebSocketEndHandler)
	if !ok {
		return false, nil
	}
	return true, x.WebSocketEnd(ctx, h.Flow)
}

func (h TCPStartHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(TCPStartHandler)
	if !ok {
		return false, nil
	}
	return true, x.TCPStart(ctx, h.Flow)
}

func (h TCPMessageHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(TCPMessageHandler)
	if !ok {
		return false, nil
	}
	return true, x.TCPMessage(ctx, h.Flow)
}

func (h TCPEndHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(TCPEndHandler)
	if !ok {
		return false, nil
	}
	return true, x.TCPEnd(ctx, h.Flow)
}

func (h TCPErrorHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(TCPErrorHandler)
	if !ok {
		return false, nil
	}
	return true, x.TCPError(ctx, h.Flow)
}

func (h UDPStartHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(UDPStartHandler)
	if !ok {
		return false, nil
	}
	return true, x.UDPStart(ctx, h.Flow)
}

func (h UDPMessageHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(UDPMessageHandler)
	if !ok {
		return false, nil
	}
	return true, x.UDPMessage(ctx, h.Flow)
}

func (h UDPEndHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(UDPEndHandler)
	if !ok {
		return false, nil
	}
	return true, x.UDPEnd(ctx, h.Flow)
}

func (h UDPErrorHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(UDPErrorHandler)
	if !ok {
		return false, nil
	}
	return true, x.UDPError(ctx, h.Flow)
}

func (h DNSRequestHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(DNSRequestHandler)
	if !ok {
		return false, nil
	}
	return true, x.DNSRequest(ctx, h.Flow)
}

func (h DNSResponseHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(DNSResponseHandler)
	if !ok {
		return false, nil
	}
	return true, x.DNSResponse(ctx, h.Flow)
}

func (h DNSErrorHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(DNSErrorHandler)
	if !ok {
		return false, nil
	}
	return true, x.DNSError(ctx, h.Flow)
}

func (h TLSClientHelloHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(TLSClientHelloHandler)
	if !ok {
		return false, nil
	}
	return true, x.TLSClientHello(ctx, h.Data)
}

func (h TLSStartClientHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(TLSStartClientHandler)
	if !ok {
		return false, nil
	}
	return true, x.TLSStartClient(ctx, h.Data)
}

func (h TLSStartServerHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(TLSStartServerHandler)
	if !ok {
		return false, nil
	}
	return true, x.TLSStartServer(ctx, h.Data)
}

func (h TLSEstablishedClientHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(TLSEstablishedClientHandler)
	if !ok {
		return false, nil
	}
	return true, x.TLSEstablishedClient(ctx, h.Data)
}

func (h TLSEstablishedServerHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(TLSEstablishedServerHandler)
	if !ok {
		return false, nil
	}
	return true, x.TLSEstablishedServer(ctx, h.Data)
}

func (h TLSFailedClientHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(TLSFailedClientHandler)
	if !ok {
		return false, nil
	}
	return true, x.TLSFailedClient(ctx, h.Data)
}

func (h TLSFailedServerHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(TLSFailedServerHandler)
	if !ok {
		return false, nil
	}
	return true, x.TLSFailedServer(ctx, h.Data)
}

func (h QUICStartClientHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(QUICStartClientHandler)
	if !ok {
		return false, nil
	}
	return true, x.QUICStartClient(ctx, h.Data)
}

func (h QUICStartServerHook) invoke(ctx context.Context, a any) (bool, error) {
	x, ok := a.(QUICStartServerHandler)
	if !ok {
		return false, nil
	}
	return true, x.QUICStartServer(ctx, h.Data)
}

// hookSpec ties a hook to its handler interface. The table is the single
// list of hooks this package dispatches: registration checks addons against
// it, and the tests check every hook type against it.
type hookSpec struct {
	hook    Hook         // zero value of the hook type
	handler reflect.Type // the hook's single-method handler interface
}

// hookSpecs lists every hook in the order mitmproxy documents them.
var hookSpecs = []hookSpec{
	{LoadHook{}, reflect.TypeFor[LoadHandler]()},
	{ConfigureHook{}, reflect.TypeFor[ConfigureHandler]()},
	{RunningHook{}, reflect.TypeFor[RunningHandler]()},
	{DoneHook{}, reflect.TypeFor[DoneHandler]()},
	{UpdateHook{}, reflect.TypeFor[UpdateHandler]()},
	{AddLogHook{}, reflect.TypeFor[AddLogHandler]()},
	{NextLayerHook{}, reflect.TypeFor[NextLayerHandler]()},
	{ClientConnectedHook{}, reflect.TypeFor[ClientConnectedHandler]()},
	{ClientDisconnectedHook{}, reflect.TypeFor[ClientDisconnectedHandler]()},
	{ServerConnectHook{}, reflect.TypeFor[ServerConnectHandler]()},
	{ServerConnectedHook{}, reflect.TypeFor[ServerConnectedHandler]()},
	{ServerDisconnectedHook{}, reflect.TypeFor[ServerDisconnectedHandler]()},
	{ServerConnectErrorHook{}, reflect.TypeFor[ServerConnectErrorHandler]()},
	{Socks5AuthHook{}, reflect.TypeFor[Socks5AuthHandler]()},
	{RequestHeadersHook{}, reflect.TypeFor[RequestHeadersHandler]()},
	{RequestHook{}, reflect.TypeFor[RequestHandler]()},
	{ResponseHeadersHook{}, reflect.TypeFor[ResponseHeadersHandler]()},
	{ResponseHook{}, reflect.TypeFor[ResponseHandler]()},
	{ErrorHook{}, reflect.TypeFor[ErrorHandler]()},
	{HTTPConnectHook{}, reflect.TypeFor[HTTPConnectHandler]()},
	{HTTPConnectUpstreamHook{}, reflect.TypeFor[HTTPConnectUpstreamHandler]()},
	{HTTPConnectedHook{}, reflect.TypeFor[HTTPConnectedHandler]()},
	{HTTPConnectErrorHook{}, reflect.TypeFor[HTTPConnectErrorHandler]()},
	{WebSocketStartHook{}, reflect.TypeFor[WebSocketStartHandler]()},
	{WebSocketMessageHook{}, reflect.TypeFor[WebSocketMessageHandler]()},
	{WebSocketEndHook{}, reflect.TypeFor[WebSocketEndHandler]()},
	{TCPStartHook{}, reflect.TypeFor[TCPStartHandler]()},
	{TCPMessageHook{}, reflect.TypeFor[TCPMessageHandler]()},
	{TCPEndHook{}, reflect.TypeFor[TCPEndHandler]()},
	{TCPErrorHook{}, reflect.TypeFor[TCPErrorHandler]()},
	{UDPStartHook{}, reflect.TypeFor[UDPStartHandler]()},
	{UDPMessageHook{}, reflect.TypeFor[UDPMessageHandler]()},
	{UDPEndHook{}, reflect.TypeFor[UDPEndHandler]()},
	{UDPErrorHook{}, reflect.TypeFor[UDPErrorHandler]()},
	{DNSRequestHook{}, reflect.TypeFor[DNSRequestHandler]()},
	{DNSResponseHook{}, reflect.TypeFor[DNSResponseHandler]()},
	{DNSErrorHook{}, reflect.TypeFor[DNSErrorHandler]()},
	{TLSClientHelloHook{}, reflect.TypeFor[TLSClientHelloHandler]()},
	{TLSStartClientHook{}, reflect.TypeFor[TLSStartClientHandler]()},
	{TLSStartServerHook{}, reflect.TypeFor[TLSStartServerHandler]()},
	{TLSEstablishedClientHook{}, reflect.TypeFor[TLSEstablishedClientHandler]()},
	{TLSEstablishedServerHook{}, reflect.TypeFor[TLSEstablishedServerHandler]()},
	{TLSFailedClientHook{}, reflect.TypeFor[TLSFailedClientHandler]()},
	{TLSFailedServerHook{}, reflect.TypeFor[TLSFailedServerHandler]()},
	{QUICStartClientHook{}, reflect.TypeFor[QUICStartClientHandler]()},
	{QUICStartServerHook{}, reflect.TypeFor[QUICStartServerHandler]()},
}

// flowHook is implemented by the hooks whose argument is a flow. After
// such a hook, [Manager.Hook] fires update with the flow, as mitmproxy does
// for every lifecycle event whose first argument is a flow.
type flowHook interface {
	Hook
	// flowArg returns the hook's flow, or nil when the hook carries none.
	flowArg() flow.Flow
}

func (h RequestHeadersHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h RequestHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h ResponseHeadersHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h ResponseHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h ErrorHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h HTTPConnectHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h HTTPConnectUpstreamHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h HTTPConnectedHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h HTTPConnectErrorHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h WebSocketStartHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h WebSocketMessageHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h WebSocketEndHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h TCPStartHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h TCPMessageHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h TCPEndHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h TCPErrorHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h UDPStartHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h UDPMessageHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h UDPEndHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h UDPErrorHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h DNSRequestHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h DNSResponseHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}

func (h DNSErrorHook) flowArg() flow.Flow {
	if h.Flow == nil {
		return nil
	}
	return h.Flow
}
