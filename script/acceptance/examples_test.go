// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package acceptance_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/dns"
)

func TestScriptExamples(t *testing.T) {
	t.Run("examples", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"anatomy":                  {func(t *testing.T) { httpExample(t, "anatomy") }},
			"anatomy2":                 {func(t *testing.T) { httpExample(t, "anatomy2") }},
			"commands-simple":          {func(t *testing.T) { httpExample(t, "commands-simple") }},
			"dns-simple":               {dnsExample},
			"http-add-header":          {func(t *testing.T) { httpExample(t, "http-add-header") }},
			"http-modify-form":         {func(t *testing.T) { httpExample(t, "http-modify-form") }},
			"http-modify-query-string": {func(t *testing.T) { httpExample(t, "http-modify-query-string") }},
			"http-redirect-requests":   {func(t *testing.T) { httpExample(t, "http-redirect-requests") }},
			"http-reply-from-proxy":    {func(t *testing.T) { httpExample(t, "http-reply-from-proxy") }},
			"http-stream-simple":       {func(t *testing.T) { httpExample(t, "http-stream-simple") }},
			"http-trailers":            {func(t *testing.T) { httpExample(t, "http-trailers") }},
			"internet-in-mirror":       {func(t *testing.T) { httpExample(t, "internet-in-mirror") }},
			"log-events":               {logExample},
			"nonblocking":              {nonblockingExample},
			"options-simple":           {func(t *testing.T) { httpExample(t, "options-simple") }},
			"shutdown":                 {shutdownExample},
			"tcp-simple":               {tcpExample},
			"websocket-simple":         {websocketExample},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}

func TestScriptExamplesUpstream(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		t.Run("TestScripts", func(t *testing.T) {
			tests := map[string]struct{ port string }{
				"test_add_header":            {"anatomy2"},
				"test_modify_form":           {"http-modify-form"},
				"test_modify_querystring":    {"http-modify-query-string"},
				"test_redirect_requests":     {"http-redirect-requests"},
				"test_send_reply_from_proxy": {"http-reply-from-proxy"},
			}
			for name, tt := range tests {
				t.Run(name, func(t *testing.T) { httpExample(t, tt.port) })
			}
		})
	})
}

func httpExample(t *testing.T, name string) {
	t.Helper()
	originBody := "origin body\x00\xff</head>"
	origin, seen := ownedOrigin(t, originBody)
	paths := []string{examplePath(name)}
	var args []string
	if name == "options-simple" {
		args = append(args, "--set", "addheader=true")
	}
	p := startProxy(t, origin.URL, paths, args...)
	if name == "http-redirect-requests" {
		p.route.expect("mitmproxy.org")
	}
	client := proxyClient(t, p)
	switch name {
	case "http-reply-from-proxy":
		got := send(t, client, "GET", "http://example.com/path", "", nil)
		equal(t, 200, got.status)
		equal(t, "Hello World", got.body)
		equal(t, "text/html", got.headers.Get("Content-Type"))
		select {
		case r := <-seen:
			t.Fatalf("synthetic reply reached origin: %+v", r)
		default:
		}
	case "http-redirect-requests":
		send(t, client, "GET", "http://example.org/redirect", "", nil)
		r := receive(t, seen)
		equal(t, "mitmproxy.org", r.host)
		equal(t, []string{"mitmproxy.org:80"}, p.route.destinations())
	case "http-modify-form":
		for _, form := range []bool{true, false} {
			headers := http.Header{}
			want := "foo=bar"
			if form {
				headers.Set("Content-Type", "application/x-www-form-urlencoded")
				want = "a=b&mitmproxy=rocks"
			}
			send(t, client, "POST", origin.URL+"/form", "a=b", headers)
			r := receive(t, seen)
			equal(t, want, r.body)
			equal(t, "application/x-www-form-urlencoded", r.headers.Get("Content-Type"))
		}
	case "http-modify-query-string":
		for _, path := range []string{"/", "/?a=b"} {
			send(t, client, "GET", origin.URL+path, "", nil)
			r := receive(t, seen)
			want := "/?mitmproxy=rocks"
			if path != "/" {
				want = "/?a=b&mitmproxy=rocks"
			}
			equal(t, want, r.path)
		}
	case "http-trailers":
		got := send(t, client, "POST", origin.URL+"/inject_trailers", "request body", nil)
		r := receive(t, seen)
		equal(t, "foobar", r.trailers.Get("X-My-Injected-Trailer-Header"))
		equal(t, "request body", r.body)
		equal(t, "foobar", got.trailers.Get("X-My-Injected-Trailer-Header"))
		equal(t, originBody, got.body)
		p.logs.contains(t, "Injected a new request trailer")
		p.logs.contains(t, "Injected a new response trailer")
	default:
		for i := range 2 {
			got := send(t, client, "GET", origin.URL+"/example", "", nil)
			r := receive(t, seen)
			equal(t, 200, got.status)
			wantBody := originBody
			if name == "internet-in-mirror" {
				wantBody = "origin body\x00\xff<style>body {transform: scaleX(-1);}</style></head>"
			}
			equal(t, wantBody, got.body)
			switch name {
			case "anatomy":
				p.logs.contains(t, fmt.Sprintf("We've seen %d flows", i+1))
			case "anatomy2":
				equal(t, "value", r.headers.Get("myheader"))
			case "commands-simple":
				p.logs.contains(t, fmt.Sprintf("num = %d", i+1))
			case "http-add-header", "options-simple":
				equal(t, strconv.Itoa(i+1), got.headers.Get("count"))
			}
		}
	}
	if strings.Contains(p.logs.text(), "Addon error:") {
		t.Fatalf("example hook failed:\n%s", p.logs.text())
	}
}

func logExample(t *testing.T) {
	p := startProcess(t, "", "-n", "-s", examplePath("log-events"))
	p.wantExit = 1
	p.wait(t)
	for _, text := range []string{"This is some informative text.", "This is a warning.", "This is an error.", "This is an alert."} {
		equal(t, 1, strings.Count(p.logs.text(), text))
	}
}

func shutdownExample(t *testing.T) {
	origin, seen := ownedOrigin(t, "unreachable")
	p := startProxy(t, origin.URL, []string{examplePath("shutdown")})
	p.route.expect("example.com")
	client := proxyClient(t, p)
	r, err := http.NewRequestWithContext(t.Context(), "GET", "http://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(r)
	if res != nil {
		_ = res.Body.Close()
	}
	if err != nil {
		t.Logf("shutdown closed the request: %v", err)
	}
	p.wait(t)
	p.logs.contains(t, "Shutting down")
	select {
	case r := <-seen:
		equal(t, "example.com", r.host)
	default:
	}
}

func nonblockingExample(t *testing.T) { nonblockingParallel(t, false) }

func dnsExample(t *testing.T) {
	origin, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		buf := make([]byte, 4096)
		if _, addr, err := origin.ReadFrom(buf); err == nil {
			t.Errorf("spoofed DNS request unexpectedly forwarded to owned origin from %s", addr)
		}
	}()
	t.Cleanup(func() { _ = origin.Close(); <-joined })
	p := startProxy(t, "", []string{examplePath("dns-simple")}, "--mode", "reverse:dns://"+origin.LocalAddr().String())
	conn, err := net.Dial("udp", p.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	deadline(t, conn)
	for _, name := range []string{"example.com", "example.org", "example.test"} {
		query := &dns.Message{ID: 42, Query: true, Questions: []dns.Question{{Name: name, Type: dns.TypeAAAA, Class: dns.ClassIN}}}
		packet, err := dns.Pack(query)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(packet); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		answer, err := dns.Unpack(buf[:n], nil)
		if err != nil {
			t.Fatal(err)
		}
		equal(t, 42, answer.ID)
		switch name {
		case "example.com":
			equal(t, 1, len(answer.Answers))
			ip, err := answer.Answers[0].IPv6Address()
			if err != nil {
				t.Fatal(err)
			}
			equal(t, "::1", ip.String())
			equal(t, dns.ClassIN, answer.Answers[0].Class)
			equal(t, dns.DefaultTTL, answer.Answers[0].TTL)
		case "example.org":
			equal(t, dns.ResponseCodeNXDOMAIN, answer.ResponseCode)
		default:
			equal(t, 0, len(answer.Answers))
			equal(t, dns.ResponseCodeNOERROR, answer.ResponseCode)
		}
	}
}

func tcpExample(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	peer := make(chan net.Conn, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		c, err := listener.Accept()
		if err == nil {
			peer <- c
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-joined })
	p := startProxy(t, "", []string{examplePath("tcp-simple")}, "--mode", "reverse:tcp://"+listener.Addr().String())
	client, err := net.Dial("tcp", p.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	deadline(t, client)
	payload := "foo\x00\xff"
	if _, err := io.WriteString(client, payload); err != nil {
		t.Fatal(err)
	}
	server := receive(t, peer)
	defer func() { _ = server.Close() }()
	deadline(t, server)
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	equal(t, "bar\x00\xff", string(buf))
	if _, err := io.WriteString(server, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	equal(t, "bar\x00\xff", string(buf))
}

func websocketExample(t *testing.T) {
	peer := make(chan net.Conn, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"); err != nil {
			t.Error(err)
			_ = conn.Close()
			return
		}
		peer <- conn
	}))
	defer origin.Close()
	p := startProxy(t, origin.URL, []string{examplePath("websocket-simple")})
	conn, err := net.Dial("tcp", p.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	deadline(t, conn)
	if _, err := fmt.Fprintf(conn, "GET %s/ HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", origin.URL, strings.TrimPrefix(origin.URL, "http://")); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, http.StatusSwitchingProtocols, res.StatusCode)
	serverConn := receive(t, peer)
	defer func() { _ = serverConn.Close() }()
	deadline(t, serverConn)
	client, server := gows.NewClientConn(conn), gows.NewServerConn(serverConn)
	for _, direction := range []bool{true, false} {
		sender, receiver := client, server
		if !direction {
			sender, receiver = server, client
		}
		for _, message := range []string{"Hello\x00\xff", "FOOBAR must disappear", "sentinel"} {
			if err := sender.WriteFrame(gows.OpcodeBinary, true, []byte(message), false); err != nil {
				t.Fatal(err)
			}
		}
		for _, want := range []string{"HAPPY\x00\xff", "sentinel"} {
			frame, err := receiver.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			equal(t, want, string(frame.Payload))
		}
	}
}
