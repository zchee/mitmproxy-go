// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"bufio"
	"bytes"
	json "encoding/json/v2"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/zchee/gows"
)

type webPeer struct {
	conn    net.Conn
	ws      *gows.Conn
	headers http.Header
}

func openWebPeer(t *testing.T, address, password string) *webPeer {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), "GET", strings.TrimSuffix(address, "/")+"/updates", nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := new(net.Dialer).DialContext(t.Context(), "tcp", request.URL.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+password)
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Accept-Encoding", "gzip")
	if err := request.Write(conn); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 101 {
		_ = response.Body.Close()
		t.Fatalf("real upgrade status=%d", response.StatusCode)
	}
	var buffered []byte
	if n := reader.Buffered(); n != 0 {
		buffered, err = reader.Peek(n)
		if err != nil {
			t.Fatal(err)
		}
		buffered = bytes.Clone(buffered)
	}
	peer := &webPeer{conn: conn, ws: gows.NewClientConn(conn, gows.WithBuffered(buffered)), headers: response.Header}
	t.Cleanup(func() { _ = peer.ws.Abort() })
	return peer
}

func (p *webPeer) barrier(t *testing.T) {
	t.Helper()
	body := []byte(`{"type":"flows/updateFilter","payload":{"name":"root","expr":"~u never-matches-root-fixture"}}`)
	if err := p.ws.WriteFrame(gows.OpcodeText, true, body, false); err != nil {
		t.Fatal(err)
	}
	for range 16 {
		frame, err := p.ws.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if frame.Header.Opcode != gows.OpcodeText || !frame.Header.Fin || frame.Compressed {
			t.Fatalf("unexpected stream frame: %+v", frame.Header)
		}
		var envelope struct {
			Type    string         `json:"type"`
			Payload map[string]any `json:"payload"`
		}
		if err := json.Unmarshal(frame.Payload, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Type == "flows/filterUpdate" {
			want := map[string]any{"name": "root", "matching_flow_ids": []any{}}
			if diff := gocmp.Diff(want, envelope.Payload); diff != "" {
				t.Fatalf("filter envelope (-want +got):\n%s", diff)
			}
			return
		}
		if envelope.Type != "events/add" && envelope.Type != "state/update" {
			t.Fatalf("unexpected pre-barrier envelope %q", envelope.Type)
		}
	}
	t.Fatal("stream did not acknowledge the actual filter command")
}

func testWebStreamRoute(t *testing.T, h *routeHarness) {
	t.Helper()
	p := openWebPeer(t, h.server.URL, "route-test")
	if p.headers.Get("Content-Encoding") != "" || len(p.headers.Values("Sec-WebSocket-Accept")) != 1 {
		t.Fatal("upgrade compressed or duplicated its handshake headers")
	}
	auth, xsrf := false, false
	for _, cookie := range (&http.Response{Header: p.headers}).Cookies() {
		if strings.HasPrefix(cookie.Name, "mitmproxy-auth-") {
			auth = cookie.HttpOnly && cookie.SameSite == http.SameSiteStrictMode
		}
		if cookie.Name == "_mitmproxy_xsrf" {
			xsrf = !cookie.HttpOnly && cookie.SameSite == http.SameSiteStrictMode
		}
	}
	if !auth || !xsrf {
		t.Fatal("ROOT upgrade lost pending auth/XSRF cookies")
	}
	p.barrier(t)
	request, err := http.NewRequestWithContext(t.Context(), "GET", h.server.URL+"/updates", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer route-test")
	request.Header.Set("Origin", "http://other-origin.invalid")
	response, err := h.server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("origin rejection read=%v close=%v", readErr, closeErr)
	}
	if response.StatusCode != 403 || string(body) != "<html><title>403: Forbidden</title><body>403: Forbidden</body></html>" {
		t.Fatalf("ROOT origin rejection status=%d body=%q", response.StatusCode, body)
	}
}
