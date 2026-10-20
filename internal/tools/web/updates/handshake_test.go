// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package updates

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zchee/gows"
)

type hijackWriter struct {
	http.ResponseWriter
	wrap func(net.Conn) net.Conn
}

func (w hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	return w.wrap(conn), rw, nil
}

type failedHandshake struct {
	net.Conn
	short bool
}

func (c failedHandshake) Write(body []byte) (int, error) {
	if c.short {
		return c.Conn.Write(body[:len(body)/2])
	}
	return 0, io.ErrClosedPipe
}

func TestWebHandshakeHeaders(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"pending_auth_and_xsrf_cookies_on_real_101": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p, status := f.open(t, nil, nil)
			if status != 101 {
				t.Fatalf("status=%d", status)
			}
			cookies := (&http.Response{Header: p.headers}).Cookies()
			foundAuth, foundXSRF := false, false
			var requestCookies []string
			for _, cookie := range cookies {
				requestCookies = append(requestCookies, cookie.Name+"="+cookie.Value)
				switch cookie.Name {
				case "mitmproxy-auth-8081":
					foundAuth = true
					if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
						t.Fatal("auth cookie flags lost")
					}
				case "_mitmproxy_xsrf":
					foundXSRF = true
					if cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
						t.Fatal("XSRF cookie flags lost")
					}
				}
			}
			if !foundAuth || !foundXSRF || len(p.headers.Values("Set-Cookie")) < 2 {
				t.Fatal("101 dropped pending cookies")
			}
			reused, status := f.open(t, http.Header{"Cookie": {strings.Join(requestCookies, "; ")}}, nil)
			if status != 101 || reused == nil {
				t.Fatal("101 cookies cannot authenticate a second connection")
			}
			for _, name := range []string{"Upgrade", "Connection", "Sec-WebSocket-Accept"} {
				if len(p.headers.Values(name)) != 1 {
					t.Fatalf("reserved header %s duplicated", name)
				}
			}
		}},
		"unauthorized_is_http_403": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			if _, status := f.open(t, http.Header{}, nil); status != 403 {
				t.Fatalf("status=%d", status)
			}
		}},
		"compression_off": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p, status := f.open(t, http.Header{"Authorization": {"Bearer " + fixturePassword}, "Sec-WebSocket-Extensions": {"permessage-deflate"}, "Accept-Encoding": {"gzip"}}, nil)
			if status != 101 || p.headers.Get("Sec-WebSocket-Extensions") != "" || p.headers.Get("Content-Encoding") != "" {
				t.Fatal("upgrade enabled compression")
			}
		}},
		"buffered_first_masked_frame": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			body := []byte(`{"type":"flows/updateFilter","payload":{"name":"pipelined","expr":""}}`)
			frame := gows.AppendHeader(nil, gows.Header{Fin: true, Opcode: gows.OpcodeText, Masked: true, Length: int64(len(body))})
			frame = append(frame, body...)
			p, status := f.open(t, nil, frame)
			if status != 101 {
				t.Fatal("upgrade rejected")
			}
			message := p.message(t)
			if message.Type != "flows/filterUpdate" {
				t.Fatal("pipelined first frame lost")
			}
			assertJSON(t, message.Payload, map[string]any{"name": "pipelined", "matching_flow_ids": nil})
		}},
		"reserved_pending_header_rejected":                   {run: func(t *testing.T) { testPendingHeader(t, "Sec-WebSocket-Protocol", "must-not-duplicate") }},
		"crlf_pending_header_rejected":                       {run: func(t *testing.T) { testPendingHeader(t, "X-Application", "bad\r\nInjected: value") }},
		"failed_handshake_write_closes_without_registration": {run: func(t *testing.T) { testFailedHandshake(t, false) }},
		"short_handshake_write_closes_without_registration":  {run: func(t *testing.T) { testFailedHandshake(t, true) }},
	}
	for name, tt := range tests {
		t.Run(name, tt.run)
	}
	origins := map[string]struct {
		origin []string
		legacy []string
		host   string
		want   int
	}{
		"missing_allowed":              {want: 101},
		"empty_rejected":               {origin: []string{""}, want: 403},
		"same_authority":               {origin: []string{"$same"}, want: 101},
		"uppercase_origin_authority":   {origin: []string{"HTTP://LOCALHOST:8081"}, host: "localhost:8081", want: 101},
		"raw_host_case_not_normalized": {origin: []string{"http://localhost:8081"}, host: "LOCALHOST:8081", want: 403},
		"port_mismatch":                {origin: []string{"http://localhost:8082"}, host: "localhost:8081", want: 403},
		"default_port_not_removed":     {origin: []string{"http://localhost:80"}, host: "localhost", want: 403},
		"null_rejected":                {origin: []string{"null"}, want: 403},
		"userinfo_rejected":            {origin: []string{"http://user@localhost:8081"}, host: "localhost:8081", want: 403},
		"multiple_origins_rejected":    {origin: []string{"$same", "http://elsewhere"}, want: 403},
		"legacy_fallback":              {legacy: []string{"$same"}, want: 101},
		"empty_origin_blocks_legacy":   {origin: []string{""}, legacy: []string{"$same"}, want: 403},
		"origin_precedes_legacy":       {origin: []string{"$same"}, legacy: []string{"http://elsewhere"}, want: 101},
		"ipv6_authority":               {origin: []string{"http://[::1]:8081"}, host: "[::1]:8081", want: 101},
	}
	for name, tt := range origins {
		t.Run("origin/"+name, func(t *testing.T) {
			f := newFixture(t, nil)
			headers := http.Header{"Authorization": {"Bearer " + fixturePassword}}
			if tt.host != "" {
				headers["Host"] = []string{tt.host}
			}
			for key, values := range map[string][]string{"Origin": tt.origin, "Sec-WebSocket-Origin": tt.legacy} {
				if values == nil {
					continue
				}
				for _, value := range values {
					if value == "$same" {
						value = "http://" + f.server.Listener.Addr().String()
					}
					headers.Add(key, value)
				}
			}
			if _, status := f.open(t, headers, nil); status != tt.want {
				t.Fatalf("origin policy status=%d,want%d", status, tt.want)
			}
		})
	}
}

func testPendingHeader(t *testing.T, name, value string) {
	t.Helper()
	f := newFixture(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set(name, value); next.ServeHTTP(w, r) })
	})
	if _, status := f.open(t, nil, nil); status != 500 {
		t.Fatalf("invalid pending header status=%d", status)
	}
	do(t, f, func(_ context.Context) error {
		if len(f.h.clients) != 0 {
			t.Fatal("failed upgrade registered client")
		}
		return nil
	})
}

func testFailedHandshake(t *testing.T, short bool) {
	t.Helper()
	returned := make(chan struct{}, 1)
	f := newFixture(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(hijackWriter{ResponseWriter: w, wrap: func(conn net.Conn) net.Conn { return failedHandshake{Conn: conn, short: short} }}, r)
			returned <- struct{}{}
		})
	})
	conn, err := net.Dial("tcp", f.server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := "GET /updates HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer " + fixturePassword + "\r\n\r\n"
	if _, err := io.Copy(conn, bytes.NewBufferString(request)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatal("failed upgrade did not close transport")
	}
	await(t, returned)
	do(t, f, func(_ context.Context) error {
		if len(f.h.clients) != 0 {
			t.Fatal("failed handshake retained registry entry")
		}
		return nil
	})
}
