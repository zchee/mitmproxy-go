// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
	"github.com/zchee/mitmproxy-go/http"
	"github.com/zchee/mitmproxy-go/internal/state"
	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

// The builders below mirror upstream's mitmproxy.test.tflow and tutils.

func tClientConn() *connection.Client {
	c := connection.NewClient(connection.Address{Host: "127.0.0.1", Port: 22}, connection.Address{}, 946681200)
	c.TimestampTLSSetup = new(946681201.0)
	c.TimestampEnd = new(946681206.0)
	c.SNI = new("address")
	c.Cipher = new("cipher")
	c.ALPN = []byte("http/1.1")
	c.TLSVersion = connection.TLSv1_2
	c.State = connection.Open
	return c
}

func tServerConn() *connection.Server {
	s := connection.NewServer(&connection.Address{Host: "address", Port: 22})
	s.Peername = &connection.Address{Host: "192.168.0.1", Port: 22}
	s.Sockname = &connection.Address{Host: "address", Port: 22}
	s.TimestampStart = new(946681202.0)
	s.TimestampTCPSetup = new(946681203.0)
	s.TimestampTLSSetup = new(946681204.0)
	s.TimestampEnd = new(946681205.0)
	s.SNI = new("address")
	s.TLSVersion = connection.TLSv1_2
	return s
}

func tReq() *http.Request {
	return &http.Request{
		HTTPVersion: "HTTP/1.1",
		Headers: http.Headers{
			{Name: []byte("header"), Value: []byte("qvalue")},
			{Name: []byte("content-length"), Value: []byte("7")},
		},
		RawContent:     []byte("content"),
		TimestampStart: 946681200,
		TimestampEnd:   new(946681201.0),
		Host:           "address", Port: 22, Method: "GET", Scheme: "http", Path: "/path",
	}
}

func tResp() *http.Response {
	return &http.Response{
		HTTPVersion: "HTTP/1.1",
		Headers: http.Headers{
			{Name: []byte("header-response"), Value: []byte("svalue")},
			{Name: []byte("content-length"), Value: []byte("7")},
		},
		RawContent:     []byte("message"),
		TimestampStart: 946681202,
		TimestampEnd:   new(946681203.0),
		StatusCode:     200, Reason: "OK",
	}
}

func tErr() *Error { return &Error{Msg: "error", Timestamp: 946681207} }

func tWebSocket() *websocket.Data {
	return &websocket.Data{
		Messages: []*websocket.Message{
			{Type: websocket.OpBinary, FromClient: true, Content: []byte("hello binary"), Timestamp: 946681203},
			{Type: websocket.OpText, FromClient: true, Content: []byte("hello text"), Timestamp: 946681204},
			{Type: websocket.OpText, FromClient: false, Content: []byte("it's me"), Timestamp: 946681205},
		},
		ClosedByClient: new(false),
		CloseCode:      new(1000),
		CloseReason:    new("Close Reason"),
		TimestampEnd:   new(946681205.0),
	}
}

type tflowOpts struct {
	resp, err, ws bool
}

func tFlow(o tflowOpts) *HTTPFlow {
	f := NewHTTPFlow(tClientConn(), tServerConn(), true)
	f.Request = tReq()
	f.TimestampCreated = f.Request.TimestampStart
	if o.resp {
		f.Response = tResp()
	}
	if o.err {
		f.Error = tErr()
	}
	if o.ws {
		f.WebSocket = tWebSocket()
	}
	return f
}

func tTCPFlow(withErr bool) *TCPFlow {
	f := NewTCPFlow(tClientConn(), tServerConn(), true)
	f.TimestampCreated = *f.ClientConn.TimestampStart
	f.Messages = []*tcp.Message{
		{FromClient: true, Content: []byte("hello"), Timestamp: 946681204.2},
		{FromClient: false, Content: []byte("it's me"), Timestamp: 946681204.5},
	}
	if withErr {
		f.Error = tErr()
	}
	return f
}

func tUDPFlow(withErr bool) *UDPFlow {
	f := NewUDPFlow(tClientConn(), tServerConn(), true)
	f.TimestampCreated = *f.ClientConn.TimestampStart
	f.Messages = []*udp.Message{
		{FromClient: true, Content: []byte("hello"), Timestamp: 946681204.2},
		{FromClient: false, Content: []byte("it's me"), Timestamp: 946681204.5},
	}
	if withErr {
		f.Error = tErr()
	}
	return f
}

func tDNSFlow(withResp, withErr bool) *DNSFlow {
	client := tClientConn()
	client.ProxyMode = "dns"
	client.TransportProtocol = connection.UDP
	server := tServerConn()
	server.TransportProtocol = connection.UDP
	f := NewDNSFlow(client, server, true)
	f.Request = &dns.Message{
		Timestamp: new(946681200.0), ID: 42, Query: true, RecursionDesired: true,
		Questions:   []dns.Question{{Name: "dns.google", Type: dns.TypeA, Class: dns.ClassIN}},
		Answers:     []dns.ResourceRecord{},
		Authorities: []dns.ResourceRecord{},
		Additionals: []dns.ResourceRecord{},
	}
	f.TimestampCreated = *f.Request.Timestamp
	if withResp {
		f.Response = f.Request.Succeed([]dns.ResourceRecord{
			{Name: "dns.google", Type: dns.TypeA, Class: dns.ClassIN, TTL: 32, Data: []byte{8, 8, 8, 8}},
		})
	}
	if withErr {
		f.Error = tErr()
	}
	return f
}

var baseKeyOrder = []string{
	"version", "type", "id", "error", "client_conn", "server_conn", "intercepted", "is_replay",
	"marked", "metadata", "comment", "timestamp_created", "backup",
}

func TestStateKeyOrder(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		f     Flow
		extra []string
	}{
		"success: http":      {f: tFlow(tflowOpts{resp: true, ws: true}), extra: []string{"request", "response", "websocket"}},
		"success: http zero": {f: &HTTPFlow{}, extra: []string{"request", "response", "websocket"}},
		"success: tcp":       {f: tTCPFlow(false), extra: []string{"messages"}},
		"success: udp":       {f: tUDPFlow(false), extra: []string{"messages"}},
		"success: dns":       {f: tDNSFlow(true, false), extra: []string{"request", "response"}},
		"success: dns zero":  {f: &DNSFlow{}, extra: []string{"request", "response"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			want := append(append([]string{}, baseKeyOrder...), tt.extra...)
			got := tt.f.GetState()
			if diff := gocmp.Diff(want, got.Keys()); diff != "" {
				t.Errorf("key order mismatch (-want +got):\n%s", diff)
			}
			if v, _ := got.Get("type"); v != tt.f.Type() {
				t.Errorf("type = %v, want %q", v, tt.f.Type())
			}
			if v, _ := got.Get("version"); v != int64(FormatVersion) {
				t.Errorf("version = %v, want %d", v, FormatVersion)
			}
			if v, _ := got.Get("metadata"); v == nil {
				t.Error("metadata serialised as None; upstream readers index it as a dict")
			}
		})
	}
}

// fromTnetstring converts a decoded tnetstring value to a state value.
// Flow files store dictionaries in reverse insertion order, so the keys of
// the result come out reversed; SetState does not depend on key order.
func fromTnetstring(t *testing.T, v any) any {
	t.Helper()
	switch x := v.(type) {
	case *tnetstring.Dict:
		m := state.NewMap(x.Len())
		for k, e := range x.All() {
			m.Set(k, fromTnetstring(t, e))
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = fromTnetstring(t, e)
		}
		return out
	case *big.Int:
		t.Fatalf("integer %v does not fit int64", x)
	}
	return v
}

// loadFixture decodes the first flow of a flow file fixture.
func loadFixture(t *testing.T, rel string) *state.Map {
	t.Helper()
	v, _, err := tnetstring.Pop(testutil.Fixture(t, rel))
	if err != nil {
		t.Fatalf("decode %s: %v", rel, err)
	}
	m, ok := fromTnetstring(t, v).(*state.Map)
	if !ok {
		t.Fatalf("%s: top-level value is %T, not a dict", rel, v)
	}
	return m
}

func TestFixtureRoundTrip(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		rel string
		// migrate applies upstream's compat steps for older fixtures.
		migrate func(*state.Map)
		check   func(*testing.T, Flow)
	}{
		"success: corrupted_gzip_body (v21)": {
			rel: "mitmproxy/flows/corrupted_gzip_body.mitm",
			check: func(t *testing.T, f Flow) {
				h := f.(*HTTPFlow)
				if h.Request.Host != "127.0.0.1" || h.Request.Port != 5000 || h.Response.StatusCode != 200 {
					t.Errorf("decoded request/response = %v / %v", h.Request, h.Response)
				}
				if _, err := h.Response.Content(); err == nil {
					t.Error("corrupt gzip body decoded without error")
				}
				if f.Common().ClientConn.ProxyMode != "regular" {
					t.Errorf("proxy mode = %q", f.Common().ClientConn.ProxyMode)
				}
			},
		},
		"success: websocket (v20 migrated)": {
			rel: "mitmproxy/flows/websocket.mitm",
			// convert_20_21 bumps the version and renames TLS version
			// "QUIC" to "QUICv1"; this fixture has no QUIC connections.
			migrate: func(m *state.Map) { m.Set("version", int64(21)) },
			check: func(t *testing.T, f Flow) {
				h := f.(*HTTPFlow)
				if h.WebSocket == nil || len(h.WebSocket.Messages) != 1 || h.Response.StatusCode != 101 {
					t.Errorf("websocket flow decoded as %+v", h.WebSocket)
				}
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			in := loadFixture(t, tt.rel)
			if tt.migrate != nil {
				tt.migrate(in)
			}
			want := state.CopyMap(in)
			f, err := FromState(in)
			if err != nil {
				t.Fatalf("FromState: %v", err)
			}
			if in.Len() != 0 {
				t.Errorf("FromState left keys %v", in.Keys())
			}
			got := f.GetState()
			if !state.Equal(want, got) {
				t.Errorf("GetState differs from the fixture:\nwant %v\n got %v", want, got)
			}
			// Written in upstream's order regardless of the file's order.
			if diff := gocmp.Diff(append(append([]string{}, baseKeyOrder...), "request", "response", "websocket"), got.Keys()); diff != "" {
				t.Errorf("key order mismatch (-want +got):\n%s", diff)
			}
			tt.check(t, f)
		})
	}
}

func TestGetSetState(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		f Flow
	}{
		"success: http with response":  {f: tFlow(tflowOpts{resp: true})},
		"success: http with error":     {f: tFlow(tflowOpts{err: true})},
		"success: http with websocket": {f: tFlow(tflowOpts{resp: true, ws: true})},
		"success: tcp":                 {f: tTCPFlow(true)},
		"success: udp":                 {f: tUDPFlow(false)},
		"success: dns with response":   {f: tDNSFlow(true, false)},
		"success: dns with error":      {f: tDNSFlow(false, true)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// Ports test_http.py::TestHTTPFlow::test_getset_state.
			s := tt.f.GetState()
			back, err := FromState(state.CopyMap(s))
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(s, back.GetState()); diff != "" {
				t.Errorf("FromState(GetState()) mismatch (-want +got):\n%s", diff)
			}
			if back.TimestampStart() != tt.f.TimestampStart() {
				t.Errorf("TimestampStart() = %v, want %v", back.TimestampStart(), tt.f.TimestampStart())
			}
		})
	}

	// Setting the state of one flow from another, including a backup and an
	// intercepted flag.
	f := tFlow(tflowOpts{resp: true})
	f2 := f.Copy().(*HTTPFlow)
	f2.ID = f.ID
	f2.Error = NewError("e2")
	f2.Backup()
	f2.Intercept()
	if err := f.SetState(f2.GetState()); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(f2.GetState(), f.GetState()); diff != "" {
		t.Errorf("SetState from another flow mismatch (-want +got):\n%s", diff)
	}
	if !f.Intercepted() {
		t.Error("SetState did not carry the intercepted flag")
	}
}

func TestSetStateKeepsConnectionIdentity(t *testing.T) {
	t.Parallel()

	f := tFlow(tflowOpts{resp: true})
	client, server := f.ClientConn, f.ServerConn
	other := tFlow(tflowOpts{})
	other.ClientConn.State = connection.Closed
	if err := f.SetState(other.GetState()); err != nil {
		t.Fatal(err)
	}
	if f.ClientConn != client || f.ServerConn != server {
		t.Error("SetState replaced the connection objects instead of updating them")
	}
	if f.ClientConn.ID != other.ClientConn.ID {
		t.Errorf("client ID = %q, want %q", f.ClientConn.ID, other.ClientConn.ID)
	}
	if f.ClientConn.State != connection.Open {
		t.Errorf("SetState changed the unserialised socket state to %v", f.ClientConn.State)
	}
	if f.Response != nil {
		t.Error("response kept although the state has none")
	}
}

func TestSetStateErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate  func(*state.Map)
		wantErr string
	}{
		"error: unexpected fields": {
			mutate:  func(m *state.Map) { m.Set("mode", "regular") },
			wantErr: "unexpected fields in HTTPFlow.set_state: [mode]",
		},
		"error: old format version": {
			mutate:  func(m *state.Map) { m.Set("version", int64(20)) },
			wantErr: "flow format version 20, expected 21",
		},
		"error: wrong type": {
			mutate:  func(m *state.Map) { m.Set("type", "tcp") },
			wantErr: `flow type "tcp", expected "http"`,
		},
		"error: request None": {
			mutate:  func(m *state.Map) { m.Set("request", nil) },
			wantErr: `field "request": expected dict, got NoneType`,
		},
		"error: nested request field": {
			mutate: func(m *state.Map) {
				r, _ := m.Get("request")
				r.(*state.Map).Set("bogus", nil)
			},
			wantErr: "unexpected fields in Request.set_state: [bogus]",
		},
		"error: nested connection field": {
			mutate: func(m *state.Map) {
				c, _ := m.Get("client_conn")
				c.(*state.Map).Set("state", int64(3))
			},
			wantErr: "unexpected fields in Client.set_state: [state]",
		},
		"error: metadata not a dict": {
			mutate:  func(m *state.Map) { m.Set("metadata", []any{}) },
			wantErr: `field "metadata": expected dict, got list`,
		},
		"error: error with extra field": {
			mutate: func(m *state.Map) {
				e := tErr().GetState()
				e.Set("x", nil)
				m.Set("error", e)
			},
			wantErr: "unexpected fields in Error.set_state: [x]",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := tFlow(tflowOpts{resp: true}).GetState()
			tt.mutate(m)
			f := tFlow(tflowOpts{})
			client := *f.ClientConn
			before := f.GetState()
			err := f.SetState(m)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("SetState error = %v, want it to contain %q", err, tt.wantErr)
			}
			if diff := gocmp.Diff(before, f.GetState()); diff != "" {
				t.Errorf("failed SetState modified the flow (-before +after):\n%s", diff)
			}
			if diff := gocmp.Diff(client.GetState(), f.ClientConn.GetState()); diff != "" {
				t.Errorf("failed SetState modified the client connection:\n%s", diff)
			}
		})
	}

	// Backup is optional on read, as upstream reads it with a default.
	m := tFlow(tflowOpts{}).GetState()
	m.Delete("backup")
	if _, err := FromState(m); err != nil {
		t.Errorf("FromState without backup: %v", err)
	}
	unknown := tFlow(tflowOpts{}).GetState()
	unknown.Set("type", "dummy")
	if _, err := FromState(unknown); err == nil || err.Error() != "unknown flow type: dummy" {
		t.Errorf("FromState with an unknown type: %v", err)
	}
}

func TestCopy(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		f Flow
	}{
		"success: http":       {f: tFlow(tflowOpts{resp: true})},
		"success: http error": {f: tFlow(tflowOpts{err: true})},
		"success: tcp":        {f: tTCPFlow(false)},
		"success: tcp error":  {f: tTCPFlow(true)},
		"success: udp":        {f: tUDPFlow(false)},
		"success: dns":        {f: tDNSFlow(true, false)},
		"success: dns error":  {f: tDNSFlow(false, true)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// Ports test_copy from test_http.py, test_tcp.py and test_dns.py.
			c := tt.f.Copy()
			a, b := tt.f.GetState(), c.GetState()
			if a.Delete("id"); true {
				b.Delete("id")
			}
			if diff := gocmp.Diff(a, b); diff != "" {
				t.Errorf("copy state mismatch apart from id (-want +got):\n%s", diff)
			}
			if c.Common().ID == tt.f.Common().ID {
				t.Error("copy kept the flow ID")
			}
			if c.Common().Live {
				t.Error("copy is live")
			}
			if c.Common().ClientConn == tt.f.Common().ClientConn {
				t.Error("copy shares the client connection")
			}
			if tt.f.Common().Error != nil && c.Common().Error == tt.f.Common().Error {
				t.Error("copy shares the error")
			}
		})
	}

	// The copy must not share byte buffers with the original.
	f := tFlow(tflowOpts{resp: true})
	c := f.Copy().(*HTTPFlow)
	c.Request.RawContent[0] = 'X'
	c.Request.Headers[0].Value[0] = 'X'
	if f.Request.RawContent[0] == 'X' || f.Request.Headers[0].Value[0] == 'X' {
		t.Error("copy shares byte buffers with the original")
	}
	tc := tTCPFlow(false)
	tcc := tc.Copy().(*TCPFlow)
	tcc.Messages[0].Content[0] = 'X'
	if tc.Messages[0].Content[0] == 'X' || &tc.Messages == &tcc.Messages {
		t.Error("TCP copy shares messages with the original")
	}
}

func TestBackup(t *testing.T) {
	t.Parallel()

	// Ports test_http.py::TestHTTPFlow::test_backup.
	f := tFlow(tflowOpts{resp: true})
	f.Request.SetContent([]byte("foo"))
	if f.Modified() {
		t.Error("Modified() without a backup")
	}
	f.Backup()
	f.Request.SetContent([]byte("bar"))
	if !f.Modified() {
		t.Error("Modified() false after a change")
	}
	if err := f.Revert(); err != nil {
		t.Fatal(err)
	}
	if c, _ := f.Request.Content(); string(c) != "foo" {
		t.Errorf("content after Revert = %q, want foo", c)
	}
	if f.Modified() {
		t.Error("Modified() true after Revert dropped the backup")
	}

	// An in-place edit of a byte slice must not reach the backup.
	g := tFlow(tflowOpts{})
	g.Backup()
	g.Request.RawContent[0] = 'X'
	if err := g.Revert(); err != nil {
		t.Fatal(err)
	}
	if string(g.Request.RawContent) != "content" {
		t.Errorf("Revert restored %q, want the content before the in-place edit", g.Request.RawContent)
	}

	// Ports test_backup_idempotence.
	h := tFlow(tflowOpts{resp: true})
	h.Backup()
	if err := h.Revert(); err != nil {
		t.Fatal(err)
	}
	h.Backup()
	if err := h.Revert(); err != nil {
		t.Fatal(err)
	}

	// The backup is written into the state and read back.
	b := tTCPFlow(false)
	b.Backup()
	s := b.GetState()
	bk, _ := s.Get("backup")
	if bk == nil {
		t.Fatal("backup missing from the state")
	}
	back, err := FromState(state.CopyMap(s))
	if err != nil {
		t.Fatal(err)
	}
	b.Messages[0].Content = []byte("changed")
	back.(*TCPFlow).Messages[0].Content = []byte("changed")
	if err := back.Revert(); err != nil {
		t.Fatal(err)
	}
	if got := string(back.(*TCPFlow).Messages[0].Content); got != "hello" {
		t.Errorf("revert of a decoded backup gave %q, want hello", got)
	}
}

func TestInterceptResumeKill(t *testing.T) {
	t.Parallel()

	// Ports test_intercept, test_resume and test_resume_duplicated.
	f := tFlow(tflowOpts{})
	f.Resume()
	if f.Intercepted() {
		t.Error("Resume intercepted the flow")
	}
	f.Intercept()
	f.Intercept()
	if !f.Intercepted() {
		t.Error("Intercept did not intercept")
	}
	f2 := f.Copy()
	if !f2.Common().Intercepted() {
		t.Error("copy lost the intercepted flag")
	}
	f.Resume()
	f2.Common().Resume()
	if f.Intercepted() || f2.Common().Intercepted() {
		t.Error("Resume did not resume")
	}

	// Ports test_kill.
	k := tFlow(tflowOpts{})
	k.Intercept()
	k.Resume()
	if !k.Killable() {
		t.Error("live flow not killable")
	}
	if err := k.Kill(); err != nil {
		t.Fatal(err)
	}
	if k.Killable() {
		t.Error("killed flow still killable")
	}
	if err := k.Kill(); !errors.Is(err, ErrNotKillable) {
		t.Errorf("second Kill = %v, want ErrNotKillable", err)
	}
	k2 := tFlow(tflowOpts{})
	k2.Intercept()
	if err := k2.Kill(); err != nil {
		t.Fatal(err)
	}
	if k2.Error.Msg != KilledMessage || k2.Intercepted() || k2.Live {
		t.Errorf("after Kill: error=%v intercepted=%v live=%v", k2.Error, k2.Intercepted(), k2.Live)
	}
	if err := tFlow(tflowOpts{}).Copy().Common().Kill(); !errors.Is(err, ErrNotKillable) {
		t.Errorf("Kill on a copy (not live) = %v, want ErrNotKillable", err)
	}
}

func TestWaitForResume(t *testing.T) {
	t.Parallel()

	const short = 50 * time.Millisecond
	waitTimesOut := func(t *testing.T, b *Base) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), short)
		defer cancel()
		if err := b.WaitForResume(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("WaitForResume on an intercepted flow = %v, want a timeout", err)
		}
	}
	waitReturns := func(t *testing.T, b *Base) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if err := b.WaitForResume(ctx); err != nil {
			t.Fatalf("WaitForResume = %v, want nil", err)
		}
	}

	// Ports test_http.py::TestHTTPFlow::test_wait_for_resume.
	waitReturns(t, &tFlow(tflowOpts{}).Base)

	f := tFlow(tflowOpts{})
	f.Intercept()
	f.Resume()
	waitReturns(t, &f.Base)

	f = tFlow(tflowOpts{})
	f.Intercept()
	waitTimesOut(t, &f.Base)
	f.Resume()
	waitReturns(t, &f.Base)

	f = tFlow(tflowOpts{})
	f.Intercept()
	waitTimesOut(t, &f.Base)
	f.Resume()
	f.Intercept()
	waitTimesOut(t, &f.Base)
	f.Resume()
	waitReturns(t, &f.Base)

	// A waiter blocked in another goroutine is released by Resume and by
	// Kill.
	for name, release := range map[string]func(*HTTPFlow){
		"resume": func(f *HTTPFlow) { f.Resume() },
		"kill":   func(f *HTTPFlow) { _ = f.Kill() },
		"revert to a non-intercepted state": func(f *HTTPFlow) {
			_ = f.Revert()
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := tFlow(tflowOpts{})
			f.Backup()
			f.Intercept()
			done := make(chan error, 1)
			go func() { done <- f.WaitForResume(t.Context()) }()
			time.Sleep(short)
			release(f)
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("WaitForResume = %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("waiter was not released")
			}
		})
	}
}

func TestTimestampStart(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		f    Flow
		want float64
	}{
		"success: http uses the request": {f: tFlow(tflowOpts{}), want: 946681200},
		"success: tcp uses the client":   {f: tTCPFlow(false), want: 946681200},
		"success: dns uses the client":   {f: tDNSFlow(false, false), want: 946681200},
		"success: zero flows give zero":  {f: &UDPFlow{}, want: 0},
		"success: http without request":  {f: &HTTPFlow{}, want: 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := tt.f.TimestampStart(); got != tt.want {
				t.Errorf("TimestampStart() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMetadata(t *testing.T) {
	t.Parallel()

	f := tFlow(tflowOpts{})
	nested := state.NewMap(1)
	nested.Set("k", []byte("v"))
	f.Metadata.Set("z", int64(1))
	f.Metadata.Set("a", nested)
	s := f.GetState()
	md, _ := s.Get("metadata")
	if diff := gocmp.Diff([]string{"z", "a"}, md.(*state.Map).Keys()); diff != "" {
		t.Errorf("metadata order mismatch (-want +got):\n%s", diff)
	}
	// GetState deep-copies metadata, as upstream does.
	nested.Set("k2", nil)
	inner, _ := md.(*state.Map).Get("a")
	if inner.(*state.Map).Len() != 1 {
		t.Error("state metadata shares nested dicts with the flow")
	}
	nilMeta := tFlow(tflowOpts{})
	nilMeta.Metadata = nil
	if v, _ := nilMeta.GetState().Get("metadata"); v == nil || v.(*state.Map).Len() != 0 {
		t.Errorf("nil metadata serialised as %v, want an empty dict", v)
	}
}

func TestStrings(t *testing.T) {
	t.Parallel()

	if got := tTCPFlow(false).String(); got != "<TCPFlow (2 messages)>" {
		t.Errorf("TCPFlow.String() = %q", got)
	}
	if got := tUDPFlow(false).String(); got != "<UDPFlow (2 messages)>" {
		t.Errorf("UDPFlow.String() = %q", got)
	}
	if got := tErr().Error(); got != "error" {
		t.Errorf("Error.Error() = %q", got)
	}
	var buf bytes.Buffer
	fmt.Fprint(&buf, NewError("x"))
	if buf.String() != "x" {
		t.Errorf("formatted error = %q", buf.String())
	}
}
