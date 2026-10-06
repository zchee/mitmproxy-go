// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxyserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/addons/errorcheck"
	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"

	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/tcplayer"
)

// Upstream test_proxyserver.py coverage:
// test_start_stop: TestStartStop covers TCP; proxytest.TestHTTPStartStop covers HTTP.
// test_inject: TestInject covers reverse TCP; proxytest.TestCONNECTInjection covers CONNECT.
// test_inject_fail: TestInjectFail covers TCP; WebSocket and UDP inject commands
// require their unimplemented protocol layers. Go's command types reject strings.
// test_warn_no_nextlayer: TestWarnNoNextLayer.
// test_self_connect: TestSelfConnect.
// test_options: TestOptions, TestOptionMetadata and TestUnsupportedModes.
// test_startup_err: TestStartupError occupies a real listening socket.
// test_shutdown_err: upstream replaces stop with a throwing function; real socket
// close-error state is covered by modeserver.TestLastErrorAndRunning instead.
// test_validation_no_transparent, test_transparent_init: TestUnsupportedModes;
// original-destination lookup is unavailable, even with server=false.
// test_dns, test_udp: rejected modes; UDP and DNS servers are not implemented.
// test_reverse_http3_and_quic_stream, test_reverse_quic_datagram: require QUIC.
// test_regular_http3: already skipped upstream; requires HTTP/3.

func TestOptionMetadata(t *testing.T) {
	m, _, _, _ := fixture(t, false)
	tests := map[string]struct {
		typ     options.Type
		value   any
		help    string
		choices []string
	}{
		"store_streamed_bodies":      {options.TypeBool, false, "Store HTTP request and response bodies when streamed (see `stream_large_bodies`). This increases memory consumption, but makes it possible to inspect streamed bodies.", nil},
		"connection_strategy":        {options.TypeStr, "eager", "Determine when server connections should be established. When set to lazy, mitmproxy tries to defer establishing an upstream connection as long as possible. This makes it possible to use server replay while being offline. When set to eager, mitmproxy can detect protocols with server-side greetings, as well as accurately mirror TLS ALPN negotiation.", []string{"eager", "lazy"}},
		"stream_large_bodies":        {options.TypeOptStr, (*string)(nil), "Stream data to the client if request or response body exceeds the given threshold. If streamed, the body will not be stored in any way, and such responses cannot be modified. Understands k/m/g suffixes, i.e. 3m for 3 megabytes. To store streamed bodies, see `store_streamed_bodies`.", nil},
		"body_size_limit":            {options.TypeOptStr, (*string)(nil), "Byte size limit of HTTP request and response bodies. Understands k/m/g suffixes, i.e. 3m for 3 megabytes.", nil},
		"keep_host_header":           {options.TypeBool, false, "Reverse Proxy: Keep the original host header instead of rewriting it to the reverse proxy target.", nil},
		"proxy_debug":                {options.TypeBool, false, "Enable debug logs in the proxy core.", nil},
		"normalize_outbound_headers": {options.TypeBool, true, "Normalize outgoing HTTP/2 header names, but emit a warning when doing so. HTTP/2 does not allow uppercase header names. This option makes sure that HTTP/2 headers set in custom scripts are lowercased before they are sent.", nil},
		"validate_inbound_headers":   {options.TypeBool, true, "Make sure that incoming HTTP requests and responses are not malformed. Disabling this option makes mitmproxy vulnerable to HTTP smuggling attacks.", nil},
		"connect_addr":               {options.TypeOptStr, (*string)(nil), "Set the local IP address that mitmproxy should use when connecting to upstream servers.", nil},
		"max_client_connections":     {options.TypeInt, 0, "Maximum number of concurrent client connections; 0 means unlimited.", nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := m.Options.Lookup(name)
			if !ok || got.Type() != tt.typ {
				t.Fatalf("option missing or wrong type: %v", got)
			}
			if diff := gocmp.Diff(tt.value, got.Default()); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff(tt.help, got.Help()); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff(tt.choices, got.Choices()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestOptions(t *testing.T) {
	tests := map[string]struct {
		values map[string]any
		want   string
	}{
		"invalid stream threshold": {map[string]any{"stream_large_bodies": new("invalid")}, "Invalid stream_large_bodies specification: invalid"},
		"invalid body limit":       {map[string]any{"body_size_limit": new("invalid")}, "Invalid body_size_limit specification: invalid"},
		"invalid source address":   {map[string]any{"connect_addr": new("invalid")}, "Invalid value for connect_addr: 'invalid'. Specify a valid IP address."},
		"invalid mode":             {map[string]any{"mode": []string{"invalid!"}}, "Invalid proxy mode specification: invalid! (unknown mode)"},
		"negative connection cap":  {map[string]any{"max_client_connections": -1}, "max_client_connections must be nonnegative."},
		"duplicate address":        {map[string]any{"mode": []string{"regular", "reverse:example.com"}}, "Cannot spawn multiple servers on the same address: 127.0.0.1:0"},
		"most frequent duplicate":  {map[string]any{"mode": []string{"regular@10001", "reverse:a@10001", "regular@10002", "reverse:b@10002", "reverse:c@10002"}}, "Cannot spawn multiple servers on the same address: 127.0.0.1:10002"},
		"valid limits":             {map[string]any{"stream_large_bodies": new("1m"), "body_size_limit": new("1m")}, ""},
		"valid source":             {map[string]any{"connect_addr": new("1.2.3.4")}, ""},
		"reverse UDP":              {map[string]any{"mode": []string{"reverse:udp://example.com:1234"}, "server": false}, ""},
		"reverse DTLS":             {map[string]any{"mode": []string{"reverse:dtls://example.com:1234"}, "server": false}, ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, _, _, _ := fixture(t, false)
			err := m.Do(t.Context(), func(ctx context.Context) error { return m.Options.Update(ctx, tt.values) })
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if _, ok := errors.AsType[*options.OptionsError](err); !ok {
				t.Fatalf("error type = %T: %v", err, err)
			}
			if err.Error() != tt.want {
				t.Fatalf("error = %q, want %q", err, tt.want)
			}
		})
	}
}

func TestUnsupportedModes(t *testing.T) {
	tests := map[string]struct{}{
		"transparent": {}, "socks5": {}, "wireguard": {}, "local": {}, "tun": {}, "dns": {},
		"reverse:quic://example.com:1234": {}, "reverse:http3://example.com": {}, "reverse:dns://example.com": {},
	}
	for spec := range tests {
		t.Run(spec, func(t *testing.T) {
			m, _, _, _ := fixture(t, false)
			err := m.Do(t.Context(), func(ctx context.Context) error {
				return m.Options.Update(ctx, map[string]any{"mode": []string{spec}, "server": false})
			})
			want := "Proxy mode " + spec + " is not supported by mitmproxy-go yet."
			if _, ok := errors.AsType[*options.OptionsError](err); !ok || err.Error() != want {
				t.Fatalf("configure = %v, want %q", err, want)
			}
			if diff := gocmp.Diff([]string{"regular"}, m.Options.Seq("mode")); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestConnectAddress(t *testing.T) {
	m, ps, _, _ := fixture(t, false)
	tests := map[string]struct {
		value *string
		host  string
	}{
		"IPv4":  {new("1.2.3.4"), "1.2.3.4"},
		"IPv6":  {new("2001:0db8:0:0::1"), "2001:db8::1"},
		"empty": {new(""), ""}, "unset": {nil, ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			update(t, m, map[string]any{"connect_addr": tt.value})
			server := connection.NewServer(&connection.Address{Host: "example.com", Port: 80})
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				return ps.ServerConnect(ctx, &hookdata.ServerConnection{Server: server})
			}); err != nil {
				t.Fatal(err)
			}
			var want *connection.Address
			if tt.host != "" {
				want = &connection.Address{Host: tt.host}
			}
			if diff := gocmp.Diff(want, server.Sockname); diff != "" {
				t.Fatal(diff)
			}
			server.Sockname = &connection.Address{Host: "127.0.0.2", Port: 17}
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				return ps.ServerConnect(ctx, &hookdata.ServerConnection{Server: server})
			}); err != nil {
				t.Fatal(err)
			}
			if server.Sockname.Host != "127.0.0.2" || server.Sockname.Port != 17 {
				t.Fatal("overwrote explicit source")
			}
		})
	}
}

func TestWarnNoNextLayer(t *testing.T) {
	m, ps, logs, _ := fixture(t, false)
	update(t, m, map[string]any{"server": false})
	if err := ps.SetupServers(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "Warning: Running proxyserver without nextlayer addon!") {
		t.Fatal(logs.String())
	}
}

func TestStartupError(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	m, ps, logs, _ := fixture(t, false)
	port := listener.Addr().(*net.TCPAddr).Port
	update(t, m, map[string]any{"listen_port": &port})
	// A bind failure is logged, never returned: the startup error summary
	// decides whether the proxy exits.
	if err := ps.SetupServers(t.Context()); err != nil {
		t.Fatalf("SetupServers must leave bind failures to the log: %v", err)
	}
	if !strings.Contains(logs.String(), "failed to listen") {
		t.Fatal(logs.String())
	}
}

func TestStartupErrorExitsRun(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	var stderr strings.Builder
	check := errorcheck.New(errorcheck.Config{Stderr: &stderr})
	logger := slog.New(check.LogHandler())
	m := master.New(master.Config{Logger: logger})
	ps, err := New(proxy.Config{Manager: m.Addons, Options: m.Options, Connections: new(proxy.Connections), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &addontest.Recorder{}
	if err := m.Addons.Add(t.Context(), ps, check, recorder); err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	update(t, m, map[string]any{"listen_host": "127.0.0.1", "listen_port": &port})
	err = m.Run(t.Context())
	ps.workers.Wait()
	if _, ok := errors.AsType[*master.ExitError](err); !ok {
		t.Fatalf("Run error = %v, want *master.ExitError", err)
	}
	if !strings.Contains(stderr.String(), "Error logged during startup, exiting...") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if slices.Contains(recorder.Hooks(), "running") {
		t.Fatalf("running fired despite startup failure: %v", recorder.Hooks())
	}
}

func TestSelfConnect(t *testing.T) {
	m, ps, _, _ := fixture(t, false)
	if err := ps.SetupServers(t.Context()); err != nil {
		t.Fatal(err)
	}
	port := ps.ListenAddrs()[0].Port
	tests := map[string]struct {
		host     string
		port     int
		protocol connection.TransportProtocol
		blocked  bool
	}{
		"localhost":           {"localhost", port, connection.TCP, true},
		"IPv4":                {"127.0.0.1", port, connection.TCP, true},
		"IPv6":                {"::1", port, connection.TCP, true},
		"different address":   {"example.com", port, connection.TCP, false},
		"different port":      {"localhost", port + 1, connection.TCP, false},
		"different transport": {"localhost", port, connection.UDP, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			server := connection.NewServer(&connection.Address{Host: tt.host, Port: tt.port})
			server.TransportProtocol = tt.protocol
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				return ps.ServerConnect(ctx, &hookdata.ServerConnection{Server: server})
			}); err != nil {
				t.Fatal(err)
			}
			var want *string
			if tt.blocked {
				want = new("Request destination unknown. Unable to figure out where this request should be forwarded to.")
			}
			if diff := gocmp.Diff(want, server.Error); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// localInterfaceAddr returns a non-loopback address of a local interface,
// or "" when the machine has none.
func localInterfaceAddr(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		if prefix, ok := addr.(*net.IPNet); ok && !prefix.IP.IsLoopback() && !prefix.IP.IsLinkLocalUnicast() {
			return prefix.IP.String()
		}
	}
	return ""
}

// TestSelfConnectAddresses compares destinations as addresses: every
// spelling of a loopback or unspecified address, and for a wildcard listener
// every local interface address, reaches this proxy's own listener.
func TestSelfConnectAddresses(t *testing.T) {
	const refused = "Request destination unknown. Unable to figure out where this request should be forwarded to."
	tests := map[string]struct {
		listenHost string
		host       func(t *testing.T) string
		blocked    bool
	}{
		"blocked: IPv4-mapped loopback":             {listenHost: "127.0.0.1", host: literal("::ffff:127.0.0.1"), blocked: true},
		"blocked: uncompressed IPv6 loopback":       {listenHost: "127.0.0.1", host: literal("0:0:0:0:0:0:0:1"), blocked: true},
		"blocked: upper-case localhost":             {listenHost: "127.0.0.1", host: literal("LOCALHOST"), blocked: true},
		"blocked: other IPv4 loopback":              {listenHost: "127.0.0.1", host: literal("127.0.0.2"), blocked: true},
		"blocked: unspecified IPv4":                 {listenHost: "127.0.0.1", host: literal("0.0.0.0"), blocked: true},
		"blocked: unspecified IPv6":                 {listenHost: "127.0.0.1", host: literal("::"), blocked: true},
		"blocked: zoned IPv6 loopback":              {listenHost: "127.0.0.1", host: literal("::1%lo0"), blocked: true},
		"allowed: documentation address":            {listenHost: "127.0.0.1", host: literal("192.0.2.1")},
		"allowed: interface address, loopback bind": {listenHost: "127.0.0.1", host: localInterfaceAddr},
		"blocked: interface address, wildcard bind": {listenHost: "", host: localInterfaceAddr, blocked: true},
		"blocked: mapped loopback, wildcard bind":   {listenHost: "", host: literal("::ffff:127.0.0.1"), blocked: true},
		"allowed: documentation, wildcard bind":     {listenHost: "", host: literal("192.0.2.1")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			host := tt.host(t)
			if host == "" {
				t.Skip("no non-loopback interface address")
			}
			m, ps, _, _ := fixture(t, false)
			update(t, m, map[string]any{"listen_host": tt.listenHost})
			if err := ps.SetupServers(t.Context()); err != nil {
				t.Fatal(err)
			}
			port := ps.ListenAddrs()[0].Port
			server := connection.NewServer(&connection.Address{Host: host, Port: port})
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				return ps.ServerConnect(ctx, &hookdata.ServerConnection{Server: server})
			}); err != nil {
				t.Fatal(err)
			}
			var want *string
			if tt.blocked {
				want = new(refused)
			}
			if diff := gocmp.Diff(want, server.Error); diff != "" {
				t.Fatalf("listen %q, destination %s (-want +got):\n%s", tt.listenHost, net.JoinHostPort(host, strconv.Itoa(port)), diff)
			}
			other := connection.NewServer(&connection.Address{Host: host, Port: port + 1})
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				return ps.ServerConnect(ctx, &hookdata.ServerConnection{Server: other})
			}); err != nil {
				t.Fatal(err)
			}
			if other.Error != nil {
				t.Fatalf("another port was refused: %q", *other.Error)
			}
		})
	}
}

func literal(host string) func(*testing.T) string {
	return func(*testing.T) string { return host }
}

func TestStartStop(t *testing.T) {
	m, ps, logs, hooks := fixture(t, true)
	origin := echoOrigin(t)
	update(t, m, map[string]any{"mode": []string{"reverse:tcp://" + origin.Addr().String()}})
	if len(ps.ListenAddrs()) != 0 {
		t.Fatal("configured listener started before setup")
	}
	if err := ps.SetupServers(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := m.Addons.Trigger(t.Context(), addon.RunningHook{}); err != nil {
		t.Fatal(err)
	}
	addrs := ps.ListenAddrs()
	client := dial(t, addrs[0].String())
	exchange(t, client, "a", "A")
	await(t, hooks.started)
	if got := ps.String(); got != "Proxyserver(1 active conns)" {
		t.Fatal(got)
	}
	if got, err := m.Call(t.Context(), "proxyserver.active_connections"); err != nil || got != 1 {
		t.Fatalf("active_connections = %v, %v", got, err)
	}
	if err := ps.SetupServers(t.Context()); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(addrs, ps.ListenAddrs()); diff != "" {
		t.Fatal(diff)
	}
	update(t, m, map[string]any{"listen_host": "127.0.0.2", "listen_port": new(12345)})
	if diff := gocmp.Diff(addrs, ps.ListenAddrs()); diff != "" {
		t.Fatal("listen defaults restarted server: " + diff)
	}
	update(t, m, map[string]any{"server": false})
	waitState(t, logs, func() bool { return len(ps.ListenAddrs()) == 0 })
	exchange(t, client, "b", "B")
	if ps.ActiveConnections(t.Context()) != 1 {
		t.Fatal("stopping listeners canceled accepted client")
	}
	_ = client.Close()
	await(t, hooks.ended)
}

func TestConnectionLimitWarning(t *testing.T) {
	m, ps, logs, hooks := fixture(t, true)
	origin := echoOrigin(t)
	update(t, m, map[string]any{"mode": []string{"reverse:tcp://" + origin.Addr().String()}, "max_client_connections": 1})
	if err := ps.SetupServers(t.Context()); err != nil {
		t.Fatal(err)
	}
	client := dial(t, ps.ListenAddrs()[0].String())
	exchange(t, client, "a", "A")
	await(t, hooks.started)
	denied := dial(t, ps.ListenAddrs()[0].String())
	var buf [1]byte
	if n, err := denied.Read(buf[:]); n != 0 || err == nil {
		t.Fatalf("denied client read = %d, %v", n, err)
	} else if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
		stack := make([]byte, 1<<20)
		t.Fatalf("denied client remained open\n%s", stack[:runtime.Stack(stack, true)])
	}
	want := "Client connection from " + denied.LocalAddr().String() + " refused: max_client_connections (1) reached."
	waitState(t, logs, func() bool { return strings.Contains(logs.String(), want) })
	if got := strings.Count(logs.String(), want); got != 1 {
		t.Fatalf("refusal logged %d times, want once: %s", got, logs.String())
	}
	if got := ps.ActiveConnections(t.Context()); got != 1 {
		t.Fatalf("denied client changed active connections to %d", got)
	}
	_ = denied.Close()
	_ = client.Close()
	await(t, hooks.ended)
}

func TestRuntimeModeSwitch(t *testing.T) {
	m, ps, logs, hooks := fixture(t, true)
	origin := echoOrigin(t)
	update(t, m, map[string]any{"mode": []string{"reverse:tcp://" + origin.Addr().String()}})
	if err := ps.SetupServers(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := m.Addons.Trigger(t.Context(), addon.RunningHook{}); err != nil {
		t.Fatal(err)
	}
	old := ps.ListenAddrs()[0]
	client := dial(t, old.String())
	exchange(t, client, "x", "X")
	await(t, hooks.started)
	update(t, m, map[string]any{"mode": []string{"regular"}})
	waitState(t, logs, func() bool { addrs := ps.ListenAddrs(); return len(addrs) == 1 && addrs[0] != old })
	exchange(t, client, "y", "Y")
	_ = client.Close()
	await(t, hooks.ended)
}

func TestInject(t *testing.T) {
	m, ps, _, hooks := fixture(t, true)
	origin := echoOrigin(t)
	update(t, m, map[string]any{"mode": []string{"reverse:tcp://" + origin.Addr().String()}})
	if err := ps.SetupServers(t.Context()); err != nil {
		t.Fatal(err)
	}
	client := dial(t, ps.ListenAddrs()[0].String())
	exchange(t, client, "a", "A")
	f := await(t, hooks.started)
	if _, err := m.Call(t.Context(), "inject.tcp", f, false, []byte("b")); err != nil {
		t.Fatal(err)
	}
	readBytes(t, client, "B")
	if _, err := m.Call(t.Context(), "inject.tcp", f, true, []byte("c")); err != nil {
		t.Fatal(err)
	}
	readBytes(t, client, "c")
	if _, err := m.Call(t.Context(), "inject.tcp", f, true, make([]byte, 128<<10+1)); !errors.Is(err, proxy.ErrInjectionSize) {
		t.Fatalf("oversized injection = %v", err)
	}
	_ = client.Close()
	await(t, hooks.ended)
}

func TestInjectFail(t *testing.T) {
	m, _, logs, _ := fixture(t, false)
	tests := map[string]struct {
		f    flow.Flow
		want string
	}{
		"non TCP":  {testflow.TFlow(), "Cannot inject TCP messages into non-TCP flows."},
		"not live": {testflow.TTCPFlow(), "Flow is not from a live connection."},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := m.Call(t.Context(), "inject.tcp", tt.f, true, []byte("test")); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(logs.String(), tt.want) {
				t.Fatal(logs.String())
			}
		})
	}
}

type streamHooks struct {
	started chan *flow.TCPFlow
	ended   chan struct{}
}

func (h *streamHooks) TCPStart(_ context.Context, f *flow.TCPFlow) error { h.started <- f; return nil }

func (h *streamHooks) TCPEnd(context.Context, *flow.TCPFlow) error { h.ended <- struct{}{}; return nil }

type logSink struct {
	mu      sync.Mutex
	text    strings.Builder
	changed chan struct{}
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.text.Write(p)
	select {
	case s.changed <- struct{}{}:
	default:
	}
	return n, err
}
func (s *logSink) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.text.String() }

func fixture(t *testing.T, withNextLayer bool) (*master.Master, *ProxyServer, *logSink, *streamHooks) {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t) })
	logs := &logSink{changed: make(chan struct{}, 1)}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	m := master.New(master.Config{Logger: logger})
	ps, err := New(proxy.Config{Manager: m.Addons, Options: m.Options, Connections: new(proxy.Connections), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	hooks := &streamHooks{started: make(chan *flow.TCPFlow, 8), ended: make(chan struct{}, 8)}
	addons := []any{ps, hooks}
	if withNextLayer {
		addons = append(addons, nextlayer.New(m.Options))
	}
	if err := m.Addons.Add(t.Context(), addons...); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		if err := m.Do(ctx, ps.Done); err != nil {
			t.Error(err)
		}
		ps.workers.Wait()
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	update(t, m, map[string]any{"listen_host": "127.0.0.1", "listen_port": new(0)})
	return m, ps, logs, hooks
}

func update(t *testing.T, m *master.Master, values map[string]any) {
	t.Helper()
	if err := m.Do(t.Context(), func(ctx context.Context) error { return m.Options.Update(ctx, values) }); err != nil {
		t.Fatal(err)
	}
}

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(30 * time.Second):
		buf := make([]byte, 1<<20)
		t.Fatalf("timed out waiting for signal\n%s", buf[:runtime.Stack(buf, true)])
		var zero T
		return zero
	}
}

func waitState(t *testing.T, logs *logSink, ready func() bool) {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for !ready() {
		select {
		case <-logs.changed:
		case <-deadline:
			buf := make([]byte, 1<<20)
			t.Fatalf("listener state did not change\n%s\n%s", logs.String(), buf[:runtime.Stack(buf, true)])
		}
	}
}

func dial(t *testing.T, address string) net.Conn {
	t.Helper()
	client, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func exchange(t *testing.T, conn net.Conn, input, want string) {
	t.Helper()
	if _, err := io.WriteString(conn, input); err != nil {
		t.Fatal(err)
	}
	readBytes(t, conn, want)
}

func readBytes(t *testing.T, conn net.Conn, want string) {
	t.Helper()
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(want, string(buf)); diff != "" {
		t.Fatal(diff)
	}
}

func echoOrigin(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer func() { _ = conn.Close() }()
				if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
					t.Error(err)
					return
				}
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						if _, werr := fmt.Fprint(conn, strings.ToUpper(string(buf[:n]))); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			})
		}
	})
	t.Cleanup(func() { _ = listener.Close(); workers.Wait() })
	return listener
}
