// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package updates

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/zchee/gows"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/addons/proxyserver"
	"github.com/zchee/mitmproxy-go/addons/view"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/tools/web/webauth"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

const fixturePassword = "updates-test-password"

type streamFixture struct {
	m      *master.Master
	h      *Hub
	server *httptest.Server
}

func newFixture(t *testing.T, wrap func(http.Handler) http.Handler) *streamFixture {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t) })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := master.New(master.Config{Logger: logger})
	for _, spec := range []struct {
		name  string
		typ   options.Type
		value any
		help  string
	}{
		{"web_host", options.TypeStr, "127.0.0.1", "test host"},
		{"web_port", options.TypeInt, 8081, "test port"},
		{"anticomp", options.TypeBool, false, "Try to convince servers to send us un-compressed data."},
	} {
		if err := m.Options.Add(t.Context(), spec.name, spec.typ, spec.value, spec.help); err != nil {
			t.Fatal(err)
		}
	}
	v := view.New(m.Addons)
	events, err := eventstore.New(2)
	if err != nil {
		t.Fatal(err)
	}
	servers, err := proxyserver.New(proxy.Config{Manager: m.Addons, Options: m.Options, Connections: new(proxy.Connections), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	auth := webauth.New(m.Options)
	if err := m.Addons.Add(t.Context(), v, events, servers, auth); err != nil {
		t.Fatal(err)
	}
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		return m.Options.Update(ctx, map[string]any{"web_password": fixturePassword, "listen_host": "127.0.0.1", "listen_port": new(0)})
	}); err != nil {
		t.Fatal(err)
	}
	h, err := New(t.Context(), Config{Master: m, View: v, Events: events, Servers: servers, Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	var handler http.Handler = h
	if wrap != nil {
		handler = wrap(handler)
	}
	f := &streamFixture{m: m, h: h, server: httptest.NewServer(handler)}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
		defer cancel()
		if err := h.Close(ctx); err != nil {
			t.Error(err)
		}
		f.server.Close()
		if err := m.Do(ctx, servers.Done); err != nil {
			t.Error(err)
		}
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return f
}

type testPeer struct {
	conn    net.Conn
	ws      *gows.Conn
	headers http.Header
}

type wireMessage struct {
	Type    string         `json:"type"`
	Payload jsontext.Value `json:"payload,omitzero"`
}

func (f *streamFixture) open(t *testing.T, headers http.Header, pipelined []byte) (*testPeer, int) {
	t.Helper()
	address := f.server.Listener.Addr().String()
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if headers == nil {
		headers = http.Header{"Authorization": {"Bearer " + fixturePassword}}
	}
	headers = headers.Clone()
	host := headers.Get("Host")
	if host == "" {
		host = address
	}
	headers.Del("Host")
	var request bytes.Buffer
	fmt.Fprintf(&request, "GET /updates HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n", host)
	if err := headers.Write(&request); err != nil {
		t.Fatal(err)
	}
	request.WriteString("\r\n")
	request.Write(pipelined)
	if _, err := conn.Write(request.Bytes()); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		_ = response.Body.Close()
		return nil, response.StatusCode
	}
	var buffered []byte
	if n := reader.Buffered(); n != 0 {
		buffered, err = reader.Peek(n)
		if err != nil {
			t.Fatal(err)
		}
		buffered = bytes.Clone(buffered)
	}
	p := &testPeer{conn: conn, ws: gows.NewClientConn(conn, gows.WithBuffered(buffered), gows.WithReadLimit(messageLimit)), headers: response.Header}
	t.Cleanup(func() { _ = p.ws.Abort() })
	return p, response.StatusCode
}

func (f *streamFixture) connect(t *testing.T) *testPeer {
	t.Helper()
	p, status := f.open(t, nil, nil)
	if status != 101 {
		t.Fatalf("upgrade status = %d", status)
	}
	p.command(t, "ready", "")
	message := p.message(t)
	if message.Type != "flows/filterUpdate" {
		t.Fatalf("admission barrier message = %q", message.Type)
	}
	return p
}

func (p *testPeer) command(t *testing.T, name, expression string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"type": "flows/updateFilter", "payload": map[string]string{"name": name, "expr": expression}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ws.WriteFrame(gows.OpcodeBinary, true, body, false); err != nil {
		t.Fatal(err)
	}
}

func (p *testPeer) frame(t *testing.T) gows.Frame {
	t.Helper()
	if err := p.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	frame, err := p.ws.ReadFrame()
	if err != nil {
		t.Fatalf("read WebSocket frame: %v", err)
	}
	frame.Payload = bytes.Clone(frame.Payload)
	return frame
}

func (p *testPeer) message(t *testing.T) wireMessage {
	t.Helper()
	frame := p.frame(t)
	if frame.Header.Opcode != gows.OpcodeText || !frame.Header.Fin || frame.Compressed {
		t.Fatalf("unexpected frame header: %+v", frame.Header)
	}
	var message wireMessage
	if err := json.Unmarshal(frame.Payload, &message); err != nil {
		t.Fatal(err)
	}
	return message
}

func assertJSON(t *testing.T, raw []byte, want any) {
	t.Helper()
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var expected, actual any
	if err := json.Unmarshal(encoded, &expected); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &actual); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(expected, actual); diff != "" {
		t.Fatal(diff)
	}
}

func assertClose(t *testing.T, p *testPeer, code gows.CloseCode, reason string) {
	t.Helper()
	frame := p.frame(t)
	if frame.Header.Opcode != gows.OpcodeClose {
		t.Fatalf("expected Close, got opcode %d", frame.Header.Opcode)
	}
	closed, err := gows.ParseClose(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Code != code || closed.Reason != reason {
		t.Fatalf("Close = %d/%q, want %d/%q", closed.Code, closed.Reason, code, reason)
	}
	_ = p.ws.WriteFrame(gows.OpcodeClose, true, frame.Payload, false)
}

func do(t *testing.T, f *streamFixture, fn func(context.Context) error) {
	t.Helper()
	if err := f.m.Do(t.Context(), fn); err != nil {
		t.Fatal(err)
	}
}

func await[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case result := <-channel:
		return result
	case <-time.After(30 * time.Second):
		t.Fatal("owned operation did not complete")
	}
	var zero T
	return zero
}

func decode(t *testing.T, body []byte, value any) {
	t.Helper()
	if err := json.Unmarshal(body, value); err != nil {
		t.Fatal(err)
	}
}

func flowID(index int) string { return strconv.Itoa(index) }
