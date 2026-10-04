// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package addon

import (
	"context"
	"reflect"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
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
	{AddLogHook{}, reflect.TypeFor[AddLogHandler]()},
	{NextLayerHook{}, reflect.TypeFor[NextLayerHandler]()},
	{ClientConnectedHook{}, reflect.TypeFor[ClientConnectedHandler]()},
	{ClientDisconnectedHook{}, reflect.TypeFor[ClientDisconnectedHandler]()},
	{ServerConnectHook{}, reflect.TypeFor[ServerConnectHandler]()},
	{ServerConnectedHook{}, reflect.TypeFor[ServerConnectedHandler]()},
	{ServerDisconnectedHook{}, reflect.TypeFor[ServerDisconnectedHandler]()},
	{ServerConnectErrorHook{}, reflect.TypeFor[ServerConnectErrorHandler]()},
	{Socks5AuthHook{}, reflect.TypeFor[Socks5AuthHandler]()},
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
