// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package proxyserver configures and runs TCP proxy listeners.
package proxyserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/human"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/modeserver"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

// ProxyServer runs listeners and provides the live-connection commands.
// Hooks run under addon dispatch; SetupServers must run outside it. Listener
// changes are serialized outside dispatch, and never join accepted connections.
// Use New; the zero value is not usable.
type ProxyServer struct {
	manager     *addon.Manager
	opts        *options.Manager
	handler     *proxy.Handler
	connections *proxy.Connections
	limiter     modeserver.ClientLimiter
	logger      *slog.Logger
	isRunning   bool
	connectAddr *connection.Address
	instances   atomic.Pointer[serverState]
	updateMu    sync.Mutex
	startOnce   sync.Once
	lifetime    context.Context
	cancel      context.CancelFunc
	wake        chan struct{}
	workers     sync.WaitGroup
}

type serverState struct{ instances []*modeserver.Instance }

// New creates the addon using the handler's dependency configuration. Manager,
// Options and Connections must be non-nil. The caller registers the addon with
// Manager and supplies nextlayer and the protocol-layer factory imports.
func New(cfg proxy.Config) (*ProxyServer, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	// Configure carries a dispatch frame; asynchronous listener work must never
	// inherit it. SetupServers links its outside-dispatch lifetime separately.
	ctx, cancel := context.WithCancel(context.Background())
	p := &ProxyServer{manager: cfg.Manager, opts: cfg.Options, connections: cfg.Connections, logger: logger, lifetime: ctx, cancel: cancel, wake: make(chan struct{}, 1)}
	p.instances.Store(&serverState{})
	if cfg.Dialer == nil {
		cfg.Dialer = p.Dialer()
	}
	handler, err := proxy.NewHandler(cfg)
	if err != nil {
		cancel()
		return nil, err
	}
	p.handler = handler
	return p, nil
}

// Load registers the proxyserver options and live-connection commands.
func (p *ProxyServer) Load(ctx context.Context, loader *addon.Loader) error {
	for _, spec := range []struct {
		name    string
		typ     options.Type
		def     any
		help    string
		choices []string
	}{
		{"store_streamed_bodies", options.TypeBool, false, "Store HTTP request and response bodies when streamed (see `stream_large_bodies`). This increases memory consumption, but makes it possible to inspect streamed bodies.", nil},
		{"connection_strategy", options.TypeStr, "eager", "Determine when server connections should be established. When set to lazy, mitmproxy tries to defer establishing an upstream connection as long as possible. This makes it possible to use server replay while being offline. When set to eager, mitmproxy can detect protocols with server-side greetings, as well as accurately mirror TLS ALPN negotiation.", []string{"eager", "lazy"}},
		{"stream_large_bodies", options.TypeOptStr, nil, "Stream data to the client if request or response body exceeds the given threshold. If streamed, the body will not be stored in any way, and such responses cannot be modified. Understands k/m/g suffixes, i.e. 3m for 3 megabytes. To store streamed bodies, see `store_streamed_bodies`.", nil},
		{"body_size_limit", options.TypeOptStr, nil, "Byte size limit of HTTP request and response bodies. Understands k/m/g suffixes, i.e. 3m for 3 megabytes.", nil},
		{"keep_host_header", options.TypeBool, false, "Reverse Proxy: Keep the original host header instead of rewriting it to the reverse proxy target.", nil},
		{"proxy_debug", options.TypeBool, false, "Enable debug logs in the proxy core.", nil},
		{"normalize_outbound_headers", options.TypeBool, true, "Normalize outgoing HTTP/2 header names, but emit a warning when doing so. HTTP/2 does not allow uppercase header names. This option makes sure that HTTP/2 headers set in custom scripts are lowercased before they are sent.", nil},
		{"validate_inbound_headers", options.TypeBool, true, "Make sure that incoming HTTP requests and responses are not malformed. Disabling this option makes mitmproxy vulnerable to HTTP smuggling attacks.", nil},
		{"connect_addr", options.TypeOptStr, nil, "Set the local IP address that mitmproxy should use when connecting to upstream servers.", nil},
		{"max_client_connections", options.TypeInt, 0, "Maximum number of concurrent client connections; 0 means unlimited.", nil},
	} {
		if err := loader.AddOption(ctx, spec.name, spec.typ, spec.def, spec.help, spec.choices...); err != nil {
			return err
		}
	}
	if err := loader.AddCommand("proxyserver.active_connections", p.ActiveConnections); err != nil {
		return err
	}
	if err := loader.AddCommand("inject.tcp", p.InjectTCP, command.WithParams("flow", "to_client", "message")); err != nil {
		return err
	}
	if err := loader.AddCommand("inject.websocket", p.InjectWebSocket, command.WithParams("flow", "to_client", "message", "is_text"), command.WithDefault("is_text", true)); err != nil {
		return err
	}
	return loader.AddCommand("inject.udp", p.InjectUDP, command.WithParams("flow", "to_client", "message"))
}

// Configure validates option changes and schedules listener updates only when
// mode or server changes. Changing listen defaults alone leaves listeners intact.
func (p *ProxyServer) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, changed := updated["max_client_connections"]; changed {
		limit := p.opts.Int("max_client_connections")
		if limit < 0 {
			return options.Errorf("max_client_connections must be nonnegative.")
		}
		p.limiter.SetLimit(limit)
	}
	for _, name := range []string{"stream_large_bodies", "body_size_limit"} {
		if _, changed := updated[name]; changed {
			value := p.opts.OptStr(name)
			if _, err := human.ParseOptSize(value); err != nil {
				return options.Errorf("Invalid %s specification: %s", name, *value)
			}
		}
	}
	if _, changed := updated["connect_addr"]; changed {
		value := p.opts.OptStr("connect_addr")
		if value == nil || *value == "" {
			p.connectAddr = nil
		} else {
			ip, err := netip.ParseAddr(*value)
			if err != nil {
				return options.Errorf("Invalid value for connect_addr: %s. Specify a valid IP address.", pyrepr.Str(*value))
			}
			p.connectAddr = &connection.Address{Host: ip.String()}
		}
	}
	_, modeChanged := updated["mode"]
	_, serverChanged := updated["server"]
	if !modeChanged && !serverChanged {
		return nil
	}
	instances, err := p.configuredInstances()
	if err != nil {
		return err
	}
	if len(instances) > 0 && p.manager.Get("nextlayer") == nil {
		p.logger.Warn("Warning: Running proxyserver without nextlayer addon!")
	}
	if p.isRunning {
		select {
		case p.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

// Running enables asynchronous listener reconfiguration.
func (p *ProxyServer) Running(context.Context) error { p.isRunning = true; return nil }

// Done cancels listener work and clients without waiting under addon dispatch.
func (p *ProxyServer) Done(context.Context) error {
	p.isRunning = false
	p.cancel()
	p.connections.Close()
	return nil
}

// SetupServers applies the current listener configuration synchronously.
// Listener close and bind failures are logged, as upstream does, so startup
// error collection decides whether the proxy exits; the returned error is
// reserved for dispatch and lifetime failures. Call outside addon dispatch.
// The first call's context governs the listener worker and accepted
// connections until canceled or Done is called.
func (p *ProxyServer) SetupServers(ctx context.Context) error {
	p.startOnce.Do(func() {
		context.AfterFunc(ctx, p.cancel)
		p.workers.Go(p.run)
	})
	return p.reconcile(ctx)
}

func (p *ProxyServer) run() {
	defer func() {
		p.updateMu.Lock()
		defer p.updateMu.Unlock()
		state := p.instances.Swap(&serverState{})
		for _, instance := range state.instances {
			if err := instance.Stop(); err != nil {
				p.logger.Error(err.Error())
			}
		}
		p.connections.Close()
	}()
	for {
		select {
		case <-p.lifetime.Done():
			return
		case <-p.wake:
			_ = p.reconcile(p.lifetime)
		}
	}
}

func (p *ProxyServer) configuredInstances() ([]*modeserver.Instance, error) {
	cfg := modeserver.Config{Handler: p.handler, ClientLimiter: &p.limiter, ListenHost: p.opts.Str("listen_host"), ListenPort: p.opts.OptInt("listen_port"), Logger: p.logger}
	var instances []*modeserver.Instance
	var addresses []connection.Address
	counts := make(map[connection.Address]int)
	for _, spec := range p.opts.Seq("mode") {
		mode, err := modespec.Parse(spec)
		if err != nil {
			return nil, options.Errorf("Invalid proxy mode specification: %s (%v)", spec, err)
		}
		instance, err := modeserver.New(mode, cfg)
		if err != nil {
			return nil, options.Errorf("%s", err)
		}
		instances = append(instances, instance)
		port, _ := mode.ListenPort(cfg.ListenPort)
		addr := connection.Address{Host: mode.ListenHost(cfg.ListenHost), Port: port}
		addresses = append(addresses, addr)
		counts[addr]++
	}
	var mostCommon connection.Address
	maxCount := 0
	for _, addr := range addresses {
		if counts[addr] > maxCount {
			mostCommon, maxCount = addr, counts[addr]
		}
	}
	if counts[mostCommon] > 1 {
		return nil, options.Errorf("Cannot spawn multiple servers on the same address: %s", human.FormatAddress(mostCommon.Host, mostCommon.Port))
	}
	return instances, nil
}

func (p *ProxyServer) reconcile(ctx context.Context) error {
	p.updateMu.Lock()
	defer p.updateMu.Unlock()
	if err := p.lifetime.Err(); err != nil {
		return err
	}
	var desired []*modeserver.Instance
	if err := p.manager.Do(ctx, func(context.Context) error {
		var err error
		desired, err = p.configuredInstances()
		if !p.opts.Bool("server") {
			desired = nil
		}
		return err
	}); err != nil {
		return err
	}
	old := make(map[modespec.Mode]*modeserver.Instance)
	for _, instance := range p.instances.Load().instances {
		old[instance.Mode()] = instance
	}
	var start []*modeserver.Instance
	for index, candidate := range desired {
		if existing, ok := old[candidate.Mode()]; ok {
			desired[index] = existing
			delete(old, candidate.Mode())
		} else {
			start = append(start, candidate)
		}
	}
	p.instances.Store(&serverState{instances: desired})
	for _, instance := range old {
		if err := instance.Stop(); err != nil {
			p.logger.Error(err.Error())
		}
	}
	for _, instance := range start {
		if err := instance.Start(p.lifetime); err != nil {
			p.logger.Error(err.Error())
		}
	}
	return nil
}

// ListenAddrs returns a fresh list of bound addresses, safe to read in hooks.
func (p *ProxyServer) ListenAddrs() []connection.Address {
	var addrs []connection.Address
	for _, instance := range p.instances.Load().instances {
		addrs = append(addrs, instance.ListenAddrs()...)
	}
	return addrs
}

// ActiveConnections implements proxyserver.active_connections.
func (p *ProxyServer) ActiveConnections(context.Context) int { return p.connections.Len() }

// String returns the upstream representation of the active connection count.
func (p *ProxyServer) String() string {
	return fmt.Sprintf("Proxyserver(%d active conns)", p.connections.Len())
}

// InjectTCP implements inject.tcp. Non-TCP and non-live flows log the upstream
// warning. Queue capacity, message size and message type errors reach the caller.
func (p *ProxyServer) InjectTCP(ctx context.Context, f flow.Flow, toClient bool, message []byte) error {
	if _, ok := f.(*flow.TCPFlow); !ok {
		p.logger.Warn("Cannot inject TCP messages into non-TCP flows.")
		return nil
	}
	err := p.handler.Inject(ctx, layer.Injected{Flow: f, Message: tcp.NewMessage(!toClient, message)})
	if errors.Is(err, proxy.ErrFlowNotLive) {
		p.logger.Warn("Flow is not from a live connection.")
		return nil
	}
	return err
}

// InjectWebSocket implements inject.websocket. Non-WebSocket and non-live flows
// log the upstream warning. isText selects text rather than binary messages;
// toClient selects the recipient. Queue and message errors reach the caller.
func (p *ProxyServer) InjectWebSocket(ctx context.Context, f flow.Flow, toClient bool, message []byte, isText bool) error {
	hf, ok := f.(*flow.HTTPFlow)
	if !ok || hf == nil || hf.WebSocket == nil {
		p.logger.Warn("Cannot inject WebSocket messages into non-WebSocket flows.")
		return nil
	}
	opcode := websocket.OpBinary
	if isText {
		opcode = websocket.OpText
	}
	err := p.handler.Inject(ctx, layer.Injected{Flow: f, Message: websocket.NewMessage(opcode, !toClient, message)})
	if errors.Is(err, proxy.ErrFlowNotLive) {
		p.logger.Warn("Flow is not from a live connection.")
		return nil
	}
	return err
}

// InjectUDP implements inject.udp. Non-UDP and non-live flows log the upstream
// warning. toClient selects the recipient; queue and message errors reach the caller.
func (p *ProxyServer) InjectUDP(ctx context.Context, f flow.Flow, toClient bool, message []byte) error {
	if _, ok := f.(*flow.UDPFlow); !ok {
		p.logger.Warn("Cannot inject UDP messages into non-UDP flows.")
		return nil
	}
	err := p.handler.Inject(ctx, layer.Injected{Flow: f, Message: udp.NewMessage(!toClient, message)})
	if errors.Is(err, proxy.ErrFlowNotLive) {
		p.logger.Warn("Flow is not from a live connection.")
		return nil
	}
	return err
}

// ServerConnect supplies the configured source address when absent and prevents
// a TCP connection from recursively targeting one of this proxy's listeners.
func (p *ProxyServer) ServerConnect(_ context.Context, data *hookdata.ServerConnection) error {
	server := data.Server
	if server.Sockname == nil && p.connectAddr != nil {
		source := *p.connectAddr
		server.Sockname = &source
	}
	if server.Address == nil || server.TransportProtocol != connection.TCP {
		return nil
	}
	if err := p.destinationError(*server.Address); err != nil {
		server.Error = new(err.Error())
	}
	return nil
}

var errSelfConnect = errors.New("Request destination unknown. Unable to figure out where this request should be forwarded to.") //nolint:staticcheck // Preserve upstream's user-facing refusal text.

// Dialer returns a TCP dialer that refuses resolved addresses matching this
// proxy's current listeners. Custom Config.Dialer implementations can delegate
// here after routing a destination, without bypassing the listener guard.
func (p *ProxyServer) Dialer() layer.Dialer {
	dial := proxy.NewDialer(net.Dialer{Control: p.dialControl})
	return func(ctx context.Context, server *connection.Server) (layer.Conn, error) {
		conn, err := dial(ctx, server)
		if errors.Is(err, errSelfConnect) {
			// net.Dialer wraps Control errors; the flow needs the refusal text,
			// not the socket operation and resolved address in that wrapper.
			return nil, errSelfConnect
		}
		return conn, err
	}
}

func (p *ProxyServer) dialControl(_, address string, _ syscall.RawConn) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	return p.destinationError(connection.Address{Host: host, Port: number})
}

func (p *ProxyServer) destinationError(destination connection.Address) error {
	for _, addr := range p.ListenAddrs() {
		if destination.Port == addr.Port && isListenerHost(destination.Host, addr.Host) {
			return errSelfConnect
		}
	}
	return nil
}

// isListenerHost reports whether a connection to host reaches a listener
// bound to listenHost on the same port. Addresses are compared as addresses,
// not strings, so that "::ffff:127.0.0.1" or "0:0:0:0:0:0:0:1" cannot loop
// the proxy into itself: a loopback or unspecified destination always reaches
// this host, and a wildcard listener is reached through every local interface
// address. Only the wildcard case asks the system for its interface addresses.
func isListenerHost(host, listenHost string) bool {
	host = strings.TrimSuffix(host, ".")
	if strings.EqualFold(host, "localhost") || host == listenHost {
		return true
	}
	dest, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	dest = dest.WithZone("").Unmap()
	if dest.IsLoopback() || dest.IsUnspecified() {
		return true
	}
	listen, err := netip.ParseAddr(listenHost)
	if err != nil {
		return false
	}
	listen = listen.WithZone("").Unmap()
	if !listen.IsUnspecified() {
		return dest == listen
	}
	locals, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, local := range locals {
		if prefix, ok := local.(*net.IPNet); ok {
			if addr, ok := netip.AddrFromSlice(prefix.IP); ok && addr.Unmap() == dest {
				return true
			}
		}
	}
	return false
}

var _ master.ServerSetup = (*ProxyServer)(nil)
