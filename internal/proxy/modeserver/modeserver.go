// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package modeserver owns TCP and UDP listeners for regular, reverse and upstream
// proxy modes. Stopping UDP evicts its tuples; accepted TCP connections may finish.
package modeserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/human"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"

	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/dnslayer" // Register DNS before accepting protocol traffic.
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/modes"    // Register the top layers passed to Handler.
)

// Config supplies an instance's handler and fallback listen settings.
// The handler must be non-nil; a nil Logger uses slog.Default.
// ListenPort is copied by New, so its caller retains ownership of the pointer.
type Config struct {
	// Handler owns accepted clients and their connection registry.
	Handler *proxy.Handler
	// ListenHost is used when the mode has no explicit listen host.
	ListenHost string
	// ListenPort overrides the mode's default port, unless its spec supplies one.
	ListenPort *int
	// Logger receives listen, accept and connection failures.
	Logger *slog.Logger
	// ClientLimiter shares admission capacity across instances. Nil is unlimited.
	ClientLimiter *ClientLimiter
	// ListenerFactories supplies protocol-specific UDP acceptance by reverse
	// scheme and transport. New copies registered defaults, applies explicit
	// overrides and rejects nil factories or non-UDP keys. QUIC and HTTP/3
	// remain unavailable at Start until their protocol handler integrations
	// are installed.
	ListenerFactories map[ListenerKey]ListenerFactory
}

// Instance owns a mode's TCP or UDP listeners. Start and Stop serialize lifecycle work
// and must run outside addon dispatch. Read-only accessors are safe in hooks:
// they read immutable snapshots and never wait for network I/O or handlers.
// Use New to create an instance; the zero value is not ready to serve.
type Instance struct {
	mode       modespec.Mode
	handler    *proxy.Handler
	limiter    *ClientLimiter
	host       string
	port       int
	top        hookdata.LayerSpec
	logger     *slog.Logger
	mu         sync.Mutex
	state      atomic.Pointer[instanceState]
	stopCancel func() bool
	listenTCP  func(context.Context, string, string) (net.Listener, error)
	factories  map[ListenerKey]ListenerFactory
}

type instanceState struct {
	listeners       []net.Listener
	packetListeners []io.Closer
	addrs           []connection.Address
	err             error
}

// New validates the mode and configuration without opening a listener.
// Regular, upstream and reverse modes are admitted. Reverse DNS serves UDP;
// QUIC and HTTP/3 fail at Start until their listener implementations are available.
// Unsupported modes return the same message used by proxyserver's configure.
func New(mode modespec.Mode, cfg Config) (*Instance, error) {
	if mode == nil || cfg.Handler == nil {
		return nil, errors.New("modeserver: New requires a mode and handler")
	}
	for key, factory := range cfg.ListenerFactories {
		if factory == nil || key.Transport != connection.UDP || key.Scheme == "" {
			return nil, fmt.Errorf("modeserver: invalid listener factory for %q over %q", key.Scheme, key.Transport)
		}
	}
	var kind hookdata.LayerKind
	switch m := mode.(type) {
	case modespec.RegularMode:
		kind = hookdata.LayerRegular
	case modespec.UpstreamMode:
		kind = hookdata.LayerUpstream
	case modespec.ReverseMode:
		switch m.Scheme {
		case "http", "https", "tcp", "tls", "udp", "dtls", "dns", "quic", "http3":
			kind = hookdata.LayerReverse
		}
	}
	if kind == "" {
		return nil, fmt.Errorf("Proxy mode %s is not supported by mitmproxy-go yet.", mode) //nolint:staticcheck // Preserve the user-facing unsupported-mode diagnostic.
	}
	port, ok := mode.ListenPort(cfg.ListenPort)
	if !ok || port < 0 || port > 65535 {
		return nil, fmt.Errorf("modeserver: invalid listen port %d", port)
	}
	host := mode.ListenHost(cfg.ListenHost)
	if inner, ok := strings.CutPrefix(host, "["); ok {
		host = strings.TrimSuffix(inner, "]")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	i := &Instance{mode: mode, handler: cfg.Handler, limiter: cfg.ClientLimiter, host: host, port: port, top: hookdata.LayerSpec{Kind: kind}, logger: logger}
	i.factories = registeredFactories(cfg.ListenerFactories)
	i.listenTCP = new(net.ListenConfig).Listen
	i.state.Store(&instanceState{})
	return i, nil
}

// Mode returns the immutable specification supplied to New.
func (i *Instance) Mode() modespec.Mode { return i.mode }

// IsRunning reports whether the instance has listening sockets.
func (i *Instance) IsRunning() bool { return len(i.state.Load().addrs) != 0 }

// LastError returns the most recent Start or Stop failure, cleared on success.
func (i *Instance) LastError() error { return i.state.Load().err }

// ListenAddrs returns a copy of the bound addresses, with port zero resolved.
// An empty listen host binds separate IPv4 and IPv6 sockets on the same port
// when IPv6 is available. If an ephemeral port collides on IPv6, the IPv6
// listener gets a separate ephemeral port. A stopped instance has no addresses.
func (i *Instance) ListenAddrs() []connection.Address { return slices.Clone(i.state.Load().addrs) }

// Start binds the listeners and starts accepting clients. Calling Start on a
// running instance is harmless. ctx must not carry an addon dispatch frame;
// it governs both the listeners and every accepted connection's lifetime.
// A canceled context closes the listeners and cancels the connection handlers.
func (i *Instance) Start(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.IsRunning() {
		return nil
	}
	packetMode := i.mode.TransportProtocol() == modespec.UDP
	if reverse, ok := i.mode.(modespec.ReverseMode); ok && reverse.Scheme == "dns" {
		packetMode = true
	}
	var listeners []net.Listener
	var packets []io.Closer
	var addrs []connection.Address
	var err error
	if packetMode {
		factory, factoryErr := i.packetFactory()
		if factoryErr != nil {
			i.state.Store(&instanceState{err: factoryErr})
			return factoryErr
		}
		packets, addrs, err = i.startPacketFactories(ctx, i.port, factory, i.handlePacket)
	} else {
		listeners, err = i.listen(ctx)
	}
	if err != nil {
		host := i.host
		if host == "" {
			host = "*"
		}
		var hint string
		if isAddrInUse(err) && !i.mode.Common().HasCustomListenPort {
			hint = fmt.Sprintf("\nTry specifying a different port by using `--mode %s@%d`.", i.mode, i.port+2)
		}
		err = fmt.Errorf("%s failed to listen on %s:%d with %w%s", i.mode.Description(), host, i.port, err, hint)
		i.state.Store(&instanceState{err: err})
		return err
	}
	state := &instanceState{listeners: listeners, packetListeners: packets, addrs: addrs}
	for _, listener := range listeners {
		addr := listener.Addr().(*net.TCPAddr)
		state.addrs = append(state.addrs, connection.Address{Host: addr.IP.String(), Port: addr.Port})
	}
	i.state.Store(state)
	i.stopCancel = context.AfterFunc(ctx, func() {
		i.mu.Lock()
		defer i.mu.Unlock()
		if i.state.Load() == state {
			_ = i.stopLocked()
		}
	})
	for _, listener := range listeners {
		go i.accept(ctx, listener)
	}
	i.logger.Info(i.mode.Description() + " listening at " + formatAddrs(state.addrs) + ".")
	return nil
}

// Stop closes the listening sockets, clears the bound addresses, and returns
// any close errors. UDP tuples are evicted because they share the socket. Stop
// never waits for connection goroutines or cancels accepted TCP clients.
// Call outside dispatch; cancellation of the Start context ends all clients.
func (i *Instance) Stop() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.stopLocked()
}

func (i *Instance) stopLocked() error {
	state := i.state.Load()
	if len(state.listeners) == 0 && len(state.packetListeners) == 0 {
		return nil
	}
	if i.stopCancel != nil {
		i.stopCancel()
		i.stopCancel = nil
	}
	var errs []error
	for _, listener := range state.packetListeners {
		if err := listener.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, listener := range state.listeners {
		if err := listener.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	err := errors.Join(errs...)
	i.state.Store(&instanceState{err: err})
	i.logger.Info(i.mode.Description() + " at " + formatAddrs(state.addrs) + " stopped.")
	return err
}

func (i *Instance) listen(ctx context.Context) ([]net.Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if i.host != "" {
		listener, err := i.listenTCP(ctx, "tcp", net.JoinHostPort(i.host, strconv.Itoa(i.port)))
		if err != nil {
			return nil, err
		}
		return []net.Listener{listener}, nil
	}
	ipv4, err := i.listenTCP(ctx, "tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(i.port)))
	if err != nil {
		return nil, err
	}
	port := ipv4.Addr().(*net.TCPAddr).Port
	ipv6, err := i.listenTCP(ctx, "tcp6", net.JoinHostPort("::", strconv.Itoa(port)))
	if i.port == 0 && isAddrInUse(err) {
		i.logger.Debug("Failed to listen on a single port, falling back to default behavior.", "error", err)
		ipv6, err = i.listenTCP(ctx, "tcp6", "[::]:0")
	}
	if err != nil {
		if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) {
			i.logger.Debug("Failed to listen on '::', listening on IPv4 only.", "error", err)
			return []net.Listener{ipv4}, nil
		}
		_ = ipv4.Close()
		return nil, err
	}
	return []net.Listener{ipv4, ipv6}, nil
}

func (i *Instance) accept(ctx context.Context, listener net.Listener) {
	for {
		client, err := listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
				i.logger.Error("Accepting proxy connection", "error", err)
			}
			return
		}
		if admitted, limit := i.limiter.acquire(); !admitted {
			_ = client.Close()
			i.logger.Warn(fmt.Sprintf("Client connection from %s refused: max_client_connections (%d) reached.", client.RemoteAddr(), limit))
			continue
		}
		go func() {
			defer i.limiter.release()
			if err := i.handler.Handle(ctx, client, i.mode.String(), i.top); err != nil {
				i.logger.Error("Handling proxy connection", "error", err)
			}
		}()
	}
}

func formatAddrs(addrs []connection.Address) string {
	parts := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		value := human.FormatAddress(addr.Host, addr.Port)
		if !slices.Contains(parts, value) {
			parts = append(parts, value)
		}
	}
	return strings.Join(parts, " and ")
}
