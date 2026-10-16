// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/addons/proxyauth"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/options"

	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/tcplayer"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

type observer struct {
	selected chan []byte
	dialed   chan connection.Address
	authed   chan hookdata.Socks5Auth
}

func (o *observer) NextLayer(_ context.Context, data *hookdata.NextLayer) error {
	if len(data.DataClient) == 0 {
		return nil
	}
	o.selected <- bytes.Clone(data.DataClient)
	data.Layer = hookdata.LayerStack{{Kind: hookdata.LayerTCP, Ignore: true}}
	return nil
}

func (o *observer) Socks5Auth(_ context.Context, data *hookdata.Socks5Auth) error {
	o.authed <- *data
	return nil
}

type fixture struct {
	client layer.Conn
	cancel context.CancelFunc
	done   chan error
	origin chan error
	obs    *observer
	logs   bytes.Buffer
}

func newFixture(t *testing.T, strategy string, auth *string, failDial bool) *fixture {
	t.Helper()
	f := &fixture{
		done: make(chan error, 1), origin: make(chan error, 1),
		obs: &observer{selected: make(chan []byte, 1), dialed: make(chan connection.Address, 1), authed: make(chan hookdata.Socks5Auth, 1)},
	}
	ctx, cancel := context.WithCancel(t.Context())
	f.cancel = cancel
	opts := options.New()
	if err := opts.Add(ctx, "connection_strategy", options.TypeStr, strategy, "Server connection strategy."); err != nil {
		t.Fatal(err)
	}
	manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	if err := manager.Add(ctx, proxyauth.New(opts), f.obs); err != nil {
		t.Fatal(err)
	}
	if err := manager.Do(ctx, func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"proxyauth": auth}) }); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if failDial {
		_ = listener.Close()
		f.origin <- nil
	} else {
		go func() {
			conn, err := listener.Accept()
			if err == nil {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(layertest.Timeout))
				_, err = io.Copy(conn, conn)
			}
			f.origin <- err
		}()
	}
	handler, err := proxy.NewHandler(proxy.Config{
		Manager: manager, Options: opts, Connections: &proxy.Connections{}, Logger: slog.New(slog.NewTextHandler(&f.logs, nil)),
		Dialer: func(ctx context.Context, server *connection.Server) (layer.Conn, error) {
			// This acquisition proves the dial runs outside the dispatch hold.
			if err := manager.Do(ctx, func(context.Context) error { return nil }); err != nil {
				return nil, err
			}
			f.obs.dialed <- *server.Address
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
			if err != nil {
				return nil, err
			}
			return conn.(*net.TCPConn), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var input layer.Conn
	f.client, input = layertest.Pipe(t)
	go func() { f.done <- handler.Handle(ctx, input, "socks5", hookdata.LayerSpec{Kind: "socks5"}) }()
	t.Cleanup(func() {
		cancel()
		_ = f.client.Close()
		_ = listener.Close()
		_ = await(t, f.done)
		_ = await(t, f.origin)
	})
	return f
}

func await[T any](t testing.TB, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(layertest.Timeout):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("SOCKS operation did not join:\n%s", buf[:n])
		var zero T
		return zero
	}
}

func writeBytes(t testing.TB, conn net.Conn, b []byte, trickle bool) {
	t.Helper()
	if trickle {
		for _, c := range b {
			if _, err := conn.Write([]byte{c}); err != nil {
				t.Fatal(err)
			}
		}
	} else if _, err := conn.Write(b); err != nil {
		t.Fatal(err)
	}
}

func readBytes(t testing.TB, conn net.Conn, want []byte) {
	t.Helper()
	if len(want) == 0 {
		return
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Fatalf("wire bytes (-want +got):\n%s", diff)
	}
}

func reply(code byte) []byte { return []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0} }

func connectRequest(atyp byte, host []byte) []byte {
	request := []byte{5, 1, 0, atyp}
	if atyp == 3 {
		request = append(request, byte(len(host)))
	}
	return append(append(request, host...), 0x12, 0x34)
}

func finish(t *testing.T, f *fixture) error {
	t.Helper()
	_ = f.client.Close()
	err := await(t, f.done)
	f.done <- err
	return err
}

func TestSOCKS5Handshake(t *testing.T) {
	tests := map[string]struct {
		input, want []byte
		log         string
		trickle     bool
	}{
		"no-auth only":                {input: []byte{5, 1, 0}, want: []byte{5, 0}},
		"no-auth among other methods": {input: []byte{5, 3, 2, 0, 1}, want: []byte{5, 0}},
		"no-auth one byte trickle":    {input: []byte{5, 1, 0}, want: []byte{5, 0}, trickle: true},
		"missing no-auth":             {input: []byte{5, 1, 2}, want: reply(255), log: "Client does not support SOCKS5 with no authentication."},
		"zero methods":                {input: []byte{5, 0}, want: reply(255), log: "Client does not support SOCKS5 with no authentication."},
		"HTTP mistaken for SOCKS":     {input: []byte("GET / HTTP/1.1"), log: "Probably not a SOCKS request but a regular HTTP request. Invalid SOCKS version. Expected 0x05, got 0x47"},
		"invalid version":             {input: []byte("abcd"), log: "Invalid SOCKS version. Expected 0x05, got 0x61"},
		"premature greeting close":    {input: []byte{5}, log: `Client closed connection before completing SOCKS5 handshake: b'\x05'`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "lazy", nil, false)
			writeBytes(t, f.client, tt.input, tt.trickle)
			readBytes(t, f.client, tt.want)
			if err := f.client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			_ = finish(t, f)
			if tt.log != "" && !strings.Contains(f.logs.String(), strings.ReplaceAll(tt.log, "\\", "\\\\")) {
				// Decode slog quoting by checking an unquoted JSON-independent
				// representation below when the message contains escapes.
				if !strings.Contains(f.logs.String(), tt.log) {
					t.Fatalf("missing diagnostic %q in %s", tt.log, f.logs.String())
				}
			}
			select {
			case got := <-f.obs.selected:
				t.Fatalf("control bytes reached protocol sniffing: %x", got)
			default:
			}
		})
	}
}

func TestSOCKS5Authentication(t *testing.T) {
	tests := map[string]struct {
		greeting, auth []byte
		spec           string
		user, password string
		accepted       bool
		trickle        bool
		missingMethod  bool
	}{
		"user password":              {greeting: []byte{5, 1, 2}, auth: []byte("\x01\x04user\x08password"), spec: "user:password", user: "user", password: "password", accepted: true},
		"method among others":        {greeting: []byte{5, 2, 1, 2}, auth: []byte("\x01\x04user\x08password"), spec: "user:password", user: "user", password: "password", accepted: true},
		"one byte trickle":           {greeting: []byte{5, 1, 2}, auth: []byte("\x01\x04user\x08password"), spec: "user:password", user: "user", password: "password", accepted: true, trickle: true},
		"wrong password":             {greeting: []byte{5, 2, 0, 2}, auth: []byte("\x01\x04user\x07errcode"), spec: "user:password", user: "user", password: "errcode"},
		"missing auth method":        {greeting: []byte{5, 1, 0}, spec: "user:password", missingMethod: true},
		"version not checked":        {greeting: []byte{5, 1, 2}, auth: []byte{255, 0, 0}, spec: "any", accepted: true},
		"zero lengths":               {greeting: []byte{5, 1, 2}, auth: []byte{1, 0, 0}, spec: ":", accepted: true},
		"empty user":                 {greeting: []byte{5, 1, 2}, auth: []byte{1, 0, 1, 'p'}, spec: ":p", password: "p", accepted: true},
		"empty password":             {greeting: []byte{5, 1, 2}, auth: []byte{1, 1, 'u', 0}, spec: "u:", user: "u", accepted: true},
		"backslash replacement":      {greeting: []byte{5, 1, 2}, auth: []byte{1, 2, 0xc3, 0x28, 1, 0xff}, spec: "any", user: `\xc3(`, password: `\xff`, accepted: true},
		"maximum credential lengths": {greeting: []byte{5, 1, 2}, auth: append(append(append([]byte{1, 255}, bytes.Repeat([]byte{'u'}, 255)...), 255), bytes.Repeat([]byte{'p'}, 255)...), spec: "any", user: strings.Repeat("u", 255), password: strings.Repeat("p", 255), accepted: true},
		"maximum method list":        {greeting: append([]byte{5, 255}, bytes.Repeat([]byte{2}, 255)...), auth: []byte{1, 0, 0}, spec: "any", accepted: true},
		"UTF8 credentials":           {greeting: []byte{5, 1, 2}, auth: []byte("\x01\x03日\x03本"), spec: "日:本", user: "日", password: "本", accepted: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "eager", &tt.spec, false)
			writeBytes(t, f.client, tt.greeting, tt.trickle)
			if tt.missingMethod {
				readBytes(t, f.client, reply(255))
				_ = finish(t, f)
				if !strings.Contains(f.logs.String(), "Client does not support SOCKS5 with user/password authentication.") {
					t.Fatal(f.logs.String())
				}
				return
			}
			readBytes(t, f.client, []byte{5, 2})
			writeBytes(t, f.client, tt.auth, tt.trickle)
			status := byte(1)
			if tt.accepted {
				status = 0
			}
			readBytes(t, f.client, []byte{1, status})
			data := await(t, f.obs.authed)
			if diff := gocmp.Diff([]string{tt.user, tt.password}, []string{data.Username, data.Password}); diff != "" {
				t.Fatal(diff)
			}
			if data.Valid != tt.accepted {
				t.Fatalf("auth hook validity = %v", data.Valid)
			}
			if tt.accepted {
				packet := append(connectRequest(1, []byte{127, 0, 0, 1}), []byte("applicationdata")...)
				writeBytes(t, f.client, packet, tt.trickle)
				readBytes(t, f.client, reply(0))
				readBytes(t, f.client, []byte("applicationdata"))
			}
			_ = finish(t, f)
			if !tt.accepted && !strings.Contains(f.logs.String(), "authentication failed") {
				t.Fatal("missing authentication failure diagnostic")
			}
			if strings.Contains(f.logs.String(), "errcode") {
				t.Fatal("credential present in authentication failure log")
			}
		})
	}
}

func TestSOCKS5Connect(t *testing.T) {
	tests := map[string]struct {
		atyp byte
		host []byte
		want string
	}{
		"IPv4":               {1, []byte{127, 0, 0, 1}, "127.0.0.1"},
		"IPv6":               {4, append(make([]byte, 15), 1), "::1"},
		"domain":             {3, []byte("example.com"), "example.com"},
		"domain replacement": {3, []byte{0x80, 0x81, 'a'}, "��a"},
		"maximum domain":     {3, bytes.Repeat([]byte{'a'}, 255), strings.Repeat("a", 255)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "eager", nil, false)
			writeBytes(t, f.client, []byte{5, 1, 0}, false)
			readBytes(t, f.client, []byte{5, 0})
			writeBytes(t, f.client, append(connectRequest(tt.atyp, tt.host), []byte("applicationdata")...), false)
			readBytes(t, f.client, reply(0))
			if diff := gocmp.Diff(connection.Address{Host: tt.want, Port: 0x1234}, await(t, f.obs.dialed)); diff != "" {
				t.Fatal(diff)
			}
			readBytes(t, f.client, []byte("applicationdata"))
		})
	}
	errorsToTest := map[string]struct {
		request []byte
		code    byte
		log     string
	}{
		"BIND":            {[]byte{5, 2, 0, 1, 127, 0, 0, 1, 0x12, 0x34}, 7, `Unsupported SOCKS5 request: b'\x05\x02\x00\x01\x7f'`},
		"UDP ASSOCIATE":   {[]byte{5, 3, 0, 1, 127}, 7, "Unsupported SOCKS5 request:"},
		"request version": {[]byte{4, 1, 0, 1, 127}, 7, "Unsupported SOCKS5 request:"},
		"reserved byte":   {[]byte{5, 1, 1, 1, 127}, 7, "Unsupported SOCKS5 request:"},
		"unknown ATYP":    {[]byte{5, 1, 0, 255, 0, 0}, 8, "Unknown address type: 255"},
	}
	for name, tt := range errorsToTest {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "lazy", nil, false)
			writeBytes(t, f.client, append([]byte{5, 1, 0}, tt.request...), false)
			readBytes(t, f.client, append([]byte{5, 0}, reply(tt.code)...))
			_ = finish(t, f)
			if !strings.Contains(f.logs.String(), tt.log) && !strings.Contains(f.logs.String(), strings.ReplaceAll(tt.log, "\\", "\\\\")) {
				t.Fatalf("missing diagnostic %q in %s", tt.log, f.logs.String())
			}
			select {
			case <-f.obs.dialed:
				t.Fatal("unsupported request dialed an origin")
			default:
			}
		})
	}
	t.Run("eager origin unreachable", func(t *testing.T) {
		f := newFixture(t, "eager", nil, true)
		writeBytes(t, f.client, append([]byte{5, 1, 0}, connectRequest(1, []byte{127, 0, 0, 1})...), false)
		readBytes(t, f.client, append([]byte{5, 0}, reply(4)...))
		if err := finish(t, f); err == nil {
			t.Fatal("failed origin reported success")
		}
	})
	t.Run("empty domain lazy success before dial", func(t *testing.T) {
		f := newFixture(t, "lazy", nil, false)
		writeBytes(t, f.client, append([]byte{5, 1, 0}, connectRequest(3, nil)...), false)
		readBytes(t, f.client, append([]byte{5, 0}, reply(0)...))
		select {
		case <-f.obs.dialed:
			t.Fatal("lazy empty destination dialed before handover")
		default:
		}
	})
	t.Run("zero port preserves network order", func(t *testing.T) {
		f := newFixture(t, "eager", nil, false)
		packet := connectRequest(1, []byte{127, 0, 0, 1})
		binary.BigEndian.PutUint16(packet[len(packet)-2:], 0)
		writeBytes(t, f.client, append([]byte{5, 1, 0}, packet...), false)
		readBytes(t, f.client, append([]byte{5, 0}, reply(0)...))
		if got := await(t, f.obs.dialed); got.Port != 0 {
			t.Fatalf("zero port = %d", got.Port)
		}
	})
}

func TestSOCKS5Handover(t *testing.T) {
	tests := map[string]struct {
		strategy  string
		auth      bool
		trickle   bool
		tls       bool
		coalesced bool
	}{
		"no-auth coalesced eager":       {strategy: "eager"},
		"no-auth coalesced lazy":        {strategy: "lazy"},
		"auth coalesced eager":          {strategy: "eager", auth: true},
		"auth coalesced lazy":           {strategy: "lazy", auth: true},
		"auth trickled lazy":            {strategy: "lazy", auth: true, trickle: true},
		"TLS bytes":                     {strategy: "eager", tls: true},
		"no-auth application coalesced": {strategy: "eager", coalesced: true},
		"auth application coalesced":    {strategy: "lazy", auth: true, coalesced: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var auth *string
			greeting := []byte{5, 1, 0}
			response := []byte{5, 0}
			if tt.auth {
				auth = new("any")
				greeting = []byte("\x05\x01\x02\x01\x04user\x08password")
				response = []byte{5, 2, 1, 0}
			}
			f := newFixture(t, tt.strategy, auth, false)
			payload := []byte("applicationdata")
			if tt.tls {
				payload = []byte{0x16, 3, 1, 0, 4, 1, 0, 0, 0}
			}
			packet := append(greeting, connectRequest(1, []byte{127, 0, 0, 1})...)
			if tt.coalesced {
				packet = append(packet, payload...)
			}
			writeBytes(t, f.client, packet, tt.trickle)
			readBytes(t, f.client, append(response, reply(0)...))
			if tt.strategy == "lazy" && !tt.coalesced {
				select {
				case <-f.obs.dialed:
					t.Fatal("lazy origin dial preceded application data")
				default:
				}
			} else {
				await(t, f.obs.dialed)
			}
			if !tt.coalesced {
				writeBytes(t, f.client, payload, false)
			}
			readBytes(t, f.client, payload)
			if observed := await(t, f.obs.selected); len(observed) == 0 || !bytes.HasPrefix(payload, observed) {
				t.Fatalf("sniffed handshake bytes or lost payload: got %x, want prefix of %x", observed, payload)
			}
			if err := f.client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			remaining, err := io.ReadAll(f.client)
			if err != nil || len(remaining) != 0 {
				t.Fatalf("payload replayed more than once: %x, %v", remaining, err)
			}
		})
	}
}

type testClock struct{ scheduled chan func() }

func (*testClock) Now() time.Time { return time.Time{} }

func (c *testClock) AfterFunc(delay time.Duration, callback func()) func() bool {
	if delay != layer.HeadReadTimeout {
		panic("SOCKS parser changed the fixed head bound")
	}
	var mu sync.Mutex
	started, stopped := false, false
	c.scheduled <- func() {
		mu.Lock()
		if stopped {
			mu.Unlock()
			return
		}
		started = true
		mu.Unlock()
		callback()
	}
	return func() bool {
		mu.Lock()
		defer mu.Unlock()
		if started || stopped {
			return false
		}
		stopped = true
		return true
	}
}

func TestSOCKS5Cancellation(t *testing.T) {
	t.Run("fixed head deadline", func(t *testing.T) {
		opts := options.New()
		if err := opts.Add(t.Context(), "connection_strategy", options.TypeStr, "lazy", "Server connection strategy."); err != nil {
			t.Fatal(err)
		}
		manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
		t.Cleanup(manager.Close)
		peer, input := layertest.Pipe(t)
		clock := &testClock{scheduled: make(chan func(), 1)}
		c := &layer.Context{
			Data:   &hookdata.Context{Client: connection.NewClient(connection.Address{}, connection.Address{}, 1), Server: connection.NewServer(nil), Options: opts},
			Client: proxy.Record(input), Do: manager.Do, Clock: clock,
		}
		done := make(chan error, 1)
		go func() { done <- (&socksProxy{}).Run(t.Context(), c) }()
		fire := await(t, clock.scheduled)
		writeBytes(t, peer, []byte{5}, false)
		fire()
		if err := await(t, done); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("fixed head deadline = %v", err)
		}
	})
	tests := map[string]struct {
		auth   bool
		prefix []byte
		want   []byte
		close  bool
	}{
		"cancel greeting":      {},
		"partial greeting EOF": {prefix: []byte{5}, close: true},
		"partial methods EOF":  {prefix: []byte{5, 2, 0}, close: true},
		"cancel credentials":   {auth: true, prefix: []byte{5, 1, 2}, want: []byte{5, 2}},
		"partial username EOF": {auth: true, prefix: []byte("\x05\x01\x02\x01\x08secret"), want: []byte{5, 2}, close: true},
		"partial password EOF": {auth: true, prefix: []byte("\x05\x01\x02\x01\x04user\x08secret"), want: []byte{5, 2}, close: true},
		"cancel CONNECT":       {prefix: []byte{5, 1, 0}, want: []byte{5, 0}},
		"partial CONNECT EOF":  {prefix: []byte{5, 1, 0, 5, 1, 0, 1, 127}, want: []byte{5, 0}, close: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var auth *string
			if tt.auth {
				auth = new("any")
			}
			f := newFixture(t, "lazy", auth, false)
			writeBytes(t, f.client, tt.prefix, false)
			readBytes(t, f.client, tt.want)
			if tt.close {
				_ = f.client.CloseWrite()
			} else {
				f.cancel()
			}
			// Handler normalizes client EOF/cancellation to a clean disconnect.
			// Completion and the absence of selection/dial prove fail-closed teardown.
			err := await(t, f.done)
			f.done <- err
			select {
			case <-f.obs.selected:
				t.Fatal("incomplete handshake selected a protocol")
			case <-f.obs.dialed:
				t.Fatal("incomplete handshake dialed an origin")
			default:
			}
			if tt.auth && tt.close {
				if strings.Contains(f.logs.String(), "secret") || strings.Contains(f.logs.String(), "user") || !strings.Contains(f.logs.String(), "authentication stage,") {
					t.Fatalf("credential-stage log is not redacted: %s", f.logs.String())
				}
			}
		})
	}
}
