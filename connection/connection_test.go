// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package connection

import (
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/state"
)

// clientKeys and serverKeys are the key orders upstream's get_state produces
// at flow format 21: dataclass fields in declaration order, with subclass
// redeclarations keeping the base position and new fields appended.
var (
	clientKeys = []string{
		"peername", "sockname", "id", "transport_protocol", "error", "tls", "certificate_list", "alpn",
		"alpn_offers", "cipher", "cipher_list", "tls_version", "sni", "timestamp_start", "timestamp_end",
		"timestamp_tls_setup", "mitmcert", "proxy_mode",
	}
	serverKeys = []string{
		"peername", "sockname", "id", "transport_protocol", "error", "tls", "certificate_list", "alpn",
		"alpn_offers", "cipher", "cipher_list", "tls_version", "sni", "timestamp_start", "timestamp_end",
		"timestamp_tls_setup", "address", "timestamp_tcp_setup", "via",
	}
)

// tClient mirrors upstream's mitmproxy.test.tflow.tclient_conn.
func tClient() *Client {
	c := NewClient(Address{Host: "127.0.0.1", Port: 22}, Address{Host: "", Port: 0}, 946681200)
	c.TimestampTLSSetup = new(946681201.0)
	c.TimestampEnd = new(946681206.0)
	c.SNI = new("address")
	c.Cipher = new("cipher")
	c.ALPN = []byte("http/1.1")
	c.TLSVersion = TLSv1_2
	c.State = Open
	c.CertificateList = [][]byte{}
	c.ALPNOffers = [][]byte{}
	c.CipherList = []string{}
	return c
}

// tServer mirrors upstream's mitmproxy.test.tflow.tserver_conn.
func tServer() *Server {
	s := NewServer(&Address{Host: "address", Port: 22})
	s.Peername = &Address{Host: "192.168.0.1", Port: 22}
	s.Sockname = &Address{Host: "address", Port: 22}
	s.TimestampStart = new(946681202.0)
	s.TimestampTCPSetup = new(946681203.0)
	s.TimestampTLSSetup = new(946681204.0)
	s.TimestampEnd = new(946681205.0)
	s.SNI = new("address")
	s.TLSVersion = TLSv1_2
	return s
}

func TestStateKeyOrder(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		got  *state.Map
		want []string
	}{
		"success: client": {got: tClient().GetState(), want: clientKeys},
		"success: server": {got: tServer().GetState(), want: serverKeys},
		"success: zero client": {
			got:  (&Client{}).GetState(),
			want: clientKeys,
		},
		"success: zero server": {
			got:  (&Server{}).GetState(),
			want: serverKeys,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if diff := gocmp.Diff(tt.want, tt.got.Keys()); diff != "" {
				t.Errorf("key order mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// fixtureClientState is the client_conn of the flow format 21 fixture
// corrupted_gzip_body.mitm, in get_state order.
func fixtureClientState() *state.Map {
	m := state.NewMap(18)
	m.Set("peername", []any{"127.0.0.1", int64(50566)})
	m.Set("sockname", []any{"127.0.0.1", int64(4446)})
	m.Set("id", "eab20223-fc4f-4cd4-aa49-eb9ab6a8572e")
	m.Set("transport_protocol", "tcp")
	m.Set("error", nil)
	m.Set("tls", false)
	m.Set("certificate_list", []any{})
	m.Set("alpn", nil)
	m.Set("alpn_offers", []any{})
	m.Set("cipher", nil)
	m.Set("cipher_list", []any{})
	m.Set("tls_version", nil)
	m.Set("sni", nil)
	m.Set("timestamp_start", 1731596382.1900728)
	m.Set("timestamp_end", 1731596382.2320333)
	m.Set("timestamp_tls_setup", nil)
	m.Set("mitmcert", nil)
	m.Set("proxy_mode", "regular")
	return m
}

// fixtureServerState is the server_conn of corrupted_gzip_body.mitm.
func fixtureServerState() *state.Map {
	m := state.NewMap(19)
	m.Set("peername", []any{"127.0.0.1", int64(5000)})
	m.Set("sockname", []any{"127.0.0.1", int64(53878)})
	m.Set("id", "23b14b13-0aa9-4226-a12d-5443619aef8d")
	m.Set("transport_protocol", "tcp")
	m.Set("error", nil)
	m.Set("tls", false)
	m.Set("certificate_list", []any{})
	m.Set("alpn", nil)
	m.Set("alpn_offers", []any{})
	m.Set("cipher", nil)
	m.Set("cipher_list", []any{})
	m.Set("tls_version", nil)
	m.Set("sni", nil)
	m.Set("timestamp_start", 1731596382.2019694)
	m.Set("timestamp_end", 1731596382.2312074)
	m.Set("timestamp_tls_setup", nil)
	m.Set("address", []any{"127.0.0.1", int64(5000)})
	m.Set("timestamp_tcp_setup", 1731596382.2034934)
	m.Set("via", nil)
	return m
}

func TestFixtureRoundTrip(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		state func() *state.Map
		load  func(*state.Map) (interface{ GetState() *state.Map }, error)
	}{
		"success: client": {
			state: fixtureClientState,
			load: func(m *state.Map) (interface{ GetState() *state.Map }, error) {
				return ClientFromState(m)
			},
		},
		"success: server": {
			state: fixtureServerState,
			load: func(m *state.Map) (interface{ GetState() *state.Map }, error) {
				return ServerFromState(m)
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			in := tt.state()
			c, err := tt.load(in)
			if err != nil {
				t.Fatalf("FromState: %v", err)
			}
			if in.Len() != 0 {
				t.Errorf("FromState left keys %v in the consumed state", in.Keys())
			}
			if diff := gocmp.Diff(tt.state(), c.GetState()); diff != "" {
				t.Errorf("GetState after FromState mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClientState(t *testing.T) {
	t.Parallel()

	// Ports test_connection.py::TestClient::test_state.
	c := tClient()
	c2, err := ClientFromState(c.GetState())
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(c.GetState(), c2.GetState()); diff != "" {
		t.Errorf("from_state(get_state) mismatch (-want +got):\n%s", diff)
	}

	other := tClient()
	other.TimestampStart = new(42.0)
	if err := c.SetState(other.GetState()); err != nil {
		t.Fatal(err)
	}
	if got := *c.TimestampStart; got != 42 {
		t.Errorf("timestamp_start = %v, want 42", got)
	}
	if c.State != Open {
		t.Errorf("SetState changed the unserialised connection state to %v", c.State)
	}

	c3 := c.Clone()
	c3.ID = state.NewID()
	if gocmp.Equal(c3.GetState(), c.GetState()) {
		t.Error("states with different IDs compare equal")
	}
	c.ID, c3.ID = "foo", "foo"
	if diff := gocmp.Diff(c.GetState(), c3.GetState()); diff != "" {
		t.Errorf("states with equal IDs differ (-want +got):\n%s", diff)
	}
}

func TestServerState(t *testing.T) {
	t.Parallel()

	s := tServer()
	s.Via = &ServerSpec{Scheme: "http", Address: Address{Host: "proxy", Port: 8080}}
	s.Peername = &Address{Host: "::1", Port: 443, Scope: &IPv6Scope{FlowInfo: 0, ScopeID: 3}}
	got := s.GetState()
	if v, _ := got.Get("via"); !gocmp.Equal(v, []any{"http", []any{"proxy", int64(8080)}}) {
		t.Errorf("via state = %v", v)
	}
	if v, _ := got.Get("peername"); !gocmp.Equal(v, []any{"::1", int64(443), int64(0), int64(3)}) {
		t.Errorf("4-tuple peername state = %v", v)
	}
	s2, err := ServerFromState(got.Clone())
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(s.GetState(), s2.GetState()); diff != "" {
		t.Errorf("round trip mismatch (-want +got):\n%s", diff)
	}
	if s3 := s.Clone(); s3.ID != s.ID || s3.Via == s.Via || s3.Peername.Scope == s.Peername.Scope {
		t.Error("Clone did not deep-copy pointer fields")
	}
}

func TestNoneVersusEmpty(t *testing.T) {
	t.Parallel()

	m := fixtureClientState()
	// A decoder may produce a typed nil []byte for an empty bytes value; it
	// must still read back as present-but-empty, not as None.
	m.Set("alpn", []byte(nil))
	c, err := ClientFromState(m)
	if err != nil {
		t.Fatal(err)
	}
	if c.ALPN == nil {
		t.Fatal("empty alpn bytes decoded as None")
	}
	if v, _ := c.GetState().Get("alpn"); !gocmp.Equal(v, []byte{}) {
		t.Errorf("alpn state = %#v, want empty bytes", v)
	}
	c.ALPN = nil
	if v, _ := c.GetState().Get("alpn"); v != nil {
		t.Errorf("alpn state for None = %#v, want nil", v)
	}
}

func TestSetStateErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate  func(*state.Map)
		server  bool
		wantErr string
	}{
		"error: unexpected fields": {
			mutate: func(m *state.Map) {
				m.Set("state", int64(0))
				m.Set("zzz", true)
			},
			wantErr: "unexpected fields in Client.set_state: [state zzz]",
		},
		"error: missing field": {
			mutate:  func(m *state.Map) { m.Delete("sni") },
			wantErr: `Client.set_state: missing field "sni"`,
		},
		"error: wrong type": {
			mutate:  func(m *state.Map) { m.Set("tls", int64(1)) },
			wantErr: `Client.set_state: field "tls": expected bool, got int`,
		},
		"error: invalid transport protocol": {
			mutate:  func(m *state.Map) { m.Set("transport_protocol", "sctp") },
			wantErr: "transport_protocol",
		},
		"error: invalid tls version": {
			mutate:  func(m *state.Map) { m.Set("tls_version", "QUIC") },
			wantErr: "tls_version",
		},
		"error: client peername None": {
			mutate:  func(m *state.Map) { m.Set("peername", nil) },
			wantErr: "peername must not be None",
		},
		"error: address 3-tuple": {
			mutate:  func(m *state.Map) { m.Set("peername", []any{"a", int64(1), int64(2)}) },
			wantErr: "peername",
		},
		"error: server address 4-tuple": {
			server:  true,
			mutate:  func(m *state.Map) { m.Set("address", []any{"::1", int64(1), int64(0), int64(0)}) },
			wantErr: "expected a tuple of 2 items, got 4",
		},
		"error: server unexpected fields": {
			server:  true,
			mutate:  func(m *state.Map) { m.Set("mitmcert", nil) },
			wantErr: "unexpected fields in Server.set_state: [mitmcert]",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var err error
			if tt.server {
				m := fixtureServerState()
				tt.mutate(m)
				s := tServer()
				before := s.GetState()
				err = s.SetState(m)
				if diff := gocmp.Diff(before, s.GetState()); diff != "" {
					t.Errorf("failed SetState modified the server (-before +after):\n%s", diff)
				}
			} else {
				m := fixtureClientState()
				tt.mutate(m)
				c := tClient()
				before := c.GetState()
				err = c.SetState(m)
				if diff := gocmp.Diff(before, c.GetState()); diff != "" {
					t.Errorf("failed SetState modified the client (-before +after):\n%s", diff)
				}
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("SetState error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestString(t *testing.T) {
	t.Parallel()

	client := func() *Client {
		c := NewClient(Address{Host: "127.0.0.1", Port: 52314}, Address{Host: "127.0.0.1", Port: 8080}, 1607780791)
		c.CipherList = []string{"foo", "bar"}
		return c
	}
	tests := map[string]struct {
		got  func() string
		want string
	}{
		"success: client plain": {
			got:  func() string { return client().String() },
			want: "Client(127.0.0.1:52314, state=closed)",
		},
		"success: client tls": {
			got: func() string {
				c := client()
				c.TimestampTLSSetup = new(1607780791.0)
				return c.String()
			},
			want: "Client(127.0.0.1:52314, state=closed, tls)",
		},
		"success: client alpn": {
			got: func() string {
				c := client()
				c.TimestampTLSSetup = new(1607780791.0)
				c.ALPN = []byte("foo")
				return c.String()
			},
			want: "Client(127.0.0.1:52314, state=closed, alpn=foo)",
		},
		"success: server alpn and source port": {
			got: func() string {
				s := NewServer(&Address{Host: "address", Port: 22})
				s.TimestampTLSSetup = new(1607780791.0)
				s.ALPN = []byte("foo")
				s.Sockname = &Address{Host: "127.0.0.1", Port: 54321}
				return s.String()
			},
			want: "Server(address:22, state=closed, alpn=foo, src_port=54321)",
		},
		"success: server without address": {
			got:  func() string { return NewServer(nil).String() },
			want: "Server(<no address>, state=closed)",
		},
		"success: ipv6 address": {
			got:  func() string { return Address{Host: "::1", Port: 80}.String() },
			want: "[::1]:80",
		},
		"success: ipv4-mapped address": {
			got:  func() string { return Address{Host: "::ffff:10.0.0.1", Port: 80}.String() },
			want: "10.0.0.1:80",
		},
		"success: unspecified address": {
			got:  func() string { return Address{Host: "0.0.0.0", Port: 8080}.String() },
			want: "*:8080",
		},
		"success: unspecified ipv4-mapped address": {
			got:  func() string { return Address{Host: "::ffff:0.0.0.0", Port: 8080}.String() },
			want: "*:8080",
		},
		"success: unspecified ipv6 address with zone": {
			got:  func() string { return Address{Host: "::%eth0", Port: 8080}.String() },
			want: "*:8080",
		},
		"success: ipv6 zone containing percent printed raw": {
			got:  func() string { return Address{Host: "fe80::1%a%b", Port: 443}.String() },
			want: "fe80::1%a%b:443",
		},
		"success: domain name": {
			got:  func() string { return Address{Host: "example.com", Port: 443}.String() },
			want: "example.com:443",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := tt.got(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConnected(t *testing.T) {
	t.Parallel()

	// Ports test_connection.py::TestConnection::test_basic.
	c := NewClient(Address{Host: "127.0.0.1", Port: 52314}, Address{Host: "127.0.0.1", Port: 8080}, 1607780791)
	c.State = Open
	if c.TLSEstablished() {
		t.Error("TLSEstablished before timestamp_tls_setup is set")
	}
	c.TimestampTLSSetup = new(1607780792.0)
	if !c.TLSEstablished() {
		t.Error("TLSEstablished false after timestamp_tls_setup is set")
	}
	if !c.Connected() {
		t.Error("Connected false for an open connection")
	}
	c.State = CanWrite
	if c.Connected() {
		t.Error("Connected true for a half-closed connection")
	}
	if got, want := (CanRead | CanWrite).String(), "OPEN"; got != want {
		t.Errorf("Open.String() = %q, want %q", got, want)
	}
}
