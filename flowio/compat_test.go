// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowio

import (
	"maps"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/state"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// olderFixtures are the fixtures in formats 18 to 20, with their version.
var olderFixtures = map[string]int64{
	"mitmproxy/flows/diff_data.mitm":      18,
	"mitmproxy/flows/error_log.mitm":      18,
	"mitmproxy/flows/incomplete_log.mitm": 18,
	"mitmproxy/flows/successful_log.mitm": 18,
	"mitmproxy/flows/event_stream.mitm":   20,
	"mitmproxy/flows/websocket.mitm":      20,
	"mitmproxy/dumpfile-19.mitm":          20,
}

// TestReadOlderFormats reads every fixture in formats 18 to 20 through the
// migrations into flow models.
func TestReadOlderFormats(t *testing.T) {
	for rel, version := range olderFixtures {
		t.Run(rel, func(t *testing.T) {
			raw := rawFlows(t, rel)
			for i, m := range raw {
				if v, _ := m.Get("version"); v != version {
					t.Fatalf("flow %d of the fixture has version %v, want %d", i, v, version)
				}
			}
			flows, err := readAll(t, testutil.Fixture(t, rel))
			if err != nil {
				t.Fatalf("after %d flows: %v", len(flows), err)
			}
			if len(flows) != len(raw) {
				t.Fatalf("read %d flows, want %d", len(flows), len(raw))
			}
			for i, f := range flows {
				if v, _ := f.GetState().Get("version"); v != int64(flow.FormatVersion) {
					t.Errorf("flow %d: version %v after reading, want %d", i, v, flow.FormatVersion)
				}
			}
		})
	}
}

// TestMigrateQUICFixture migrates dumpfile-19.mitm, a format 20 HTTP/3
// flow: both connections must change from TLS version "QUIC" to "QUICv1"
// and the version to 21, and nothing else may change.
func TestMigrateQUICFixture(t *testing.T) {
	for i, m := range rawFlows(t, "mitmproxy/dumpfile-19.mitm") {
		want := state.CopyMap(m)
		want.Set("version", int64(flow.FormatVersion))
		for _, name := range []string{"client_conn", "server_conn"} {
			conn, err := connDict(want, name)
			if err != nil {
				t.Fatal(err)
			}
			if v, _ := conn.Get("tls_version"); v != "QUIC" {
				t.Fatalf("flow %d: %s.tls_version = %v in the fixture, want QUIC", i, name, v)
			}
			conn.Set("tls_version", "QUICv1")
		}
		if err := migrate(m); err != nil {
			t.Fatal(err)
		}
		if !state.Equal(want, m) {
			t.Errorf("flow %d: migrated state differs from the expected one", i)
		}
	}
}

// conn18 returns a format 18 connection dictionary with the keys
// convert_18_19 reads.
func conn18(extra ...any) *state.Map {
	m := dictOf(
		"address", []any{[]byte("example.com"), int64(443)},
		"tls_extensions", nil,
		"tls_established", true,
		"cipher_name", "TLS_AES_128_GCM_SHA256",
		"timestamp_start", 1.5,
		"sni", "example.com",
		"tls_version", "TLSv1.3",
	)
	for i := 0; i < len(extra); i += 2 {
		if extra[i+1] == deleted {
			m.Delete(extra[i].(string))
			continue
		}
		m.Set(extra[i].(string), extra[i+1])
	}
	return m
}

// deleted marks a key that conn18 must remove.
var deleted = &struct{}{}

func flow18(client, server *state.Map) *state.Map {
	return dictOf("version", int64(18), "client_conn", client, "server_conn", server)
}

// connView is the part of a migrated connection the migration tests
// compare, in key order.
type connView struct {
	Keys   []string
	Values map[string]any
}

func viewOf(m *state.Map) connView {
	v := connView{Keys: m.Keys(), Values: map[string]any{}}
	maps.Insert(v.Values, m.All())
	return v
}

func TestConvert18To19(t *testing.T) {
	tests := map[string]struct {
		client, server   *state.Map
		wantClient       connView
		wantServer       connView
		wantErr          string
		wantClientSubset map[string]any
		wantServerSubset map[string]any
	}{
		"success: renames and decodes addresses": {
			client: conn18(),
			server: conn18("ip_address", []any{[]byte("10.0.0.1"), int64(443)}, "source_address", []any{"10.0.0.2", int64(5000)}, "via2", nil),
			wantClient: connView{
				Keys: []string{"timestamp_start", "sni", "tls_version", "peername", "cipher", "transport_protocol"},
				Values: map[string]any{
					"timestamp_start":    1.5,
					"sni":                "example.com",
					"tls_version":        "TLSv1.3",
					"peername":           []any{"example.com", int64(443)},
					"cipher":             "TLS_AES_128_GCM_SHA256",
					"transport_protocol": "tcp",
				},
			},
			wantServer: connView{
				Keys: []string{"address", "tls_extensions", "timestamp_start", "sni", "tls_version", "peername", "sockname", "via", "cipher", "transport_protocol"},
				Values: map[string]any{
					"address":            []any{"example.com", int64(443)},
					"tls_extensions":     nil,
					"timestamp_start":    1.5,
					"sni":                "example.com",
					"tls_version":        "TLSv1.3",
					"peername":           []any{"10.0.0.1", int64(443)},
					"sockname":           []any{"10.0.0.2", int64(5000)},
					"via":                nil,
					"cipher":             "TLS_AES_128_GCM_SHA256",
					"transport_protocol": "tcp",
				},
			},
		},
		"success: missing timestamp and None address": {
			client:           conn18("timestamp_start", deleted, "address", nil, "transport_protocol", "udp"),
			server:           conn18(),
			wantClientSubset: map[string]any{"timestamp_start": 0.0, "peername": nil, "transport_protocol": "udp"},
		},
		"success: None timestamp becomes 0.0": {
			client:           conn18("timestamp_start", nil),
			server:           conn18(),
			wantClientSubset: map[string]any{"timestamp_start": 0.0},
		},
		"success: sni True takes the address host": {
			client:           conn18(),
			server:           conn18("sni", true, "address", []any{[]byte("h\xffst"), int64(1)}),
			wantServerSubset: map[string]any{"sni": `h\xffst`, "address": []any{`h\xffst`, int64(1)}, "peername": nil, "sockname": nil, "via": nil},
		},
		"success: sni False and string hosts are kept": {
			client:           conn18("address", []any{"1.2.3.4", int64(1)}),
			server:           conn18("sni", false, "address", []any{}),
			wantClientSubset: map[string]any{"peername": []any{"1.2.3.4", int64(1)}},
			wantServerSubset: map[string]any{"sni": false, "address": []any{}},
		},
		"error: client tls_extensions missing": {
			client:  conn18("tls_extensions", deleted),
			server:  conn18(),
			wantErr: "invalid flow: client_conn.tls_extensions is missing",
		},
		"error: server tls_established missing": {
			client:  conn18(),
			server:  conn18("tls_established", deleted),
			wantErr: "invalid flow: server_conn.tls_established is missing",
		},
		"error: sni missing": {
			client:  conn18(),
			server:  conn18("sni", deleted),
			wantErr: "invalid flow: server_conn.sni is missing",
		},
		"error: sni True without an address": {
			client:  conn18(),
			server:  conn18("sni", true, "address", nil),
			wantErr: "server_conn.sni is True but server_conn.address is NoneType",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			data := flow18(tt.client, tt.server)
			err := convert18To19(data)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if v, _ := data.Get("version"); v != int64(19) {
				t.Errorf("version = %v, want 19", v)
			}
			if tt.wantClient.Keys != nil {
				if diff := gocmp.Diff(tt.wantClient, viewOf(tt.client)); diff != "" {
					t.Errorf("client_conn mismatch (-want +got):\n%s", diff)
				}
				if diff := gocmp.Diff(tt.wantServer, viewOf(tt.server)); diff != "" {
					t.Errorf("server_conn mismatch (-want +got):\n%s", diff)
				}
			}
			for conn, subset := range map[*state.Map]map[string]any{tt.client: tt.wantClientSubset, tt.server: tt.wantServerSubset} {
				for k, want := range subset {
					got, ok := conn.Get(k)
					if !ok || !state.Equal(want, got) {
						t.Errorf("%s = %#v (present %v), want %#v", k, got, ok, want)
					}
				}
			}
		})
	}
}

func TestConvert19To20And20To21(t *testing.T) {
	tests := map[string]struct {
		convert            func(*state.Map) error
		client, server     *state.Map
		wantVersion        int64
		wantClient         *state.Map
		wantServer         *state.Map
		wantErr            string
		missingClientField bool
	}{
		"success: 19 to 20 drops the state": {
			convert:     convert19To20,
			client:      dictOf("state", int64(3), "a", int64(1)),
			server:      dictOf("a", int64(2)),
			wantVersion: 20,
			wantClient:  dictOf("a", int64(1)),
			wantServer:  dictOf("a", int64(2)),
		},
		"success: 20 to 21 renames QUIC": {
			convert:     convert20To21,
			client:      dictOf("tls_version", "QUIC"),
			server:      dictOf("tls_version", "QUIC"),
			wantVersion: 21,
			wantClient:  dictOf("tls_version", "QUICv1"),
			wantServer:  dictOf("tls_version", "QUICv1"),
		},
		"success: 20 to 21 keeps other versions": {
			convert:     convert20To21,
			client:      dictOf("tls_version", nil),
			server:      dictOf("tls_version", []byte("QUIC")),
			wantVersion: 21,
			wantClient:  dictOf("tls_version", nil),
			wantServer:  dictOf("tls_version", []byte("QUIC")),
		},
		"error: 20 to 21 without tls_version": {
			convert: convert20To21,
			client:  dictOf("tls_version", "QUIC"),
			server:  dictOf(),
			wantErr: "invalid flow: server_conn.tls_version is missing",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			data := dictOf("version", tt.wantVersion-1, "client_conn", tt.client, "server_conn", tt.server)
			err := tt.convert(data)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := dictOf("version", tt.wantVersion, "client_conn", tt.wantClient, "server_conn", tt.wantServer)
			if !state.Equal(want, data) {
				t.Errorf("got %v, want %v", data, want)
			}
		})
	}
}

func TestMigrateConnectionErrors(t *testing.T) {
	tests := map[string]struct {
		data    *state.Map
		wantErr string
	}{
		"error: client_conn missing at 18":    {data: dictOf("version", int64(18)), wantErr: "invalid flow: client_conn is missing"},
		"error: server_conn missing at 18":    {data: dictOf("version", int64(18), "client_conn", conn18()), wantErr: "invalid flow: server_conn is missing"},
		"error: client_conn not a dict at 19": {data: dictOf("version", int64(19), "client_conn", nil), wantErr: "invalid flow: client_conn is a NoneType, not a dict"},
		"error: server_conn not a dict at 20": {data: dictOf("version", int64(20), "client_conn", dictOf("tls_version", nil), "server_conn", []any{}), wantErr: "invalid flow: server_conn is a list, not a dict"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := migrate(tt.data)
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestDecodeBackslashReplace(t *testing.T) {
	tests := map[string]struct {
		in   string
		want string
	}{
		"success: ASCII":                 {in: "example.com", want: "example.com"},
		"success: valid UTF-8":           {in: "bücher.example", want: "bücher.example"},
		"success: encoded U+FFFD":        {in: "\xef\xbf\xbd", want: "�"},
		"success: invalid byte":          {in: "a\xffb", want: `a\xffb`},
		"success: truncated sequence":    {in: "\xe2\x82A", want: `\xe2\x82A`},
		"success: surrogate":             {in: "\xed\xa0\x80", want: `\xed\xa0\x80`},
		"success: overlong":              {in: "\xc0\xaf", want: `\xc0\xaf`},
		"success: trailing continuation": {in: "ok\x80", want: `ok\x80`},
		"success: empty":                 {in: "", want: ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := decodeBackslashReplace([]byte(tt.in)); got != tt.want {
				t.Errorf("decodeBackslashReplace(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
