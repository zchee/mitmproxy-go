// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"fmt"
	"testing"

	"go.starlark.net/starlark"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
)

func TestScriptHooks(t *testing.T) {
	tests := map[string]struct {
		argument  string
		assertion string
		hook      func(*scriptFixture) addon.Hook
	}{
		"on_load":   {"loader", "    loader.add_option(\"hook_loaded\", \"bool\", True, \"Hook load probe.\")\n", nil},
		"configure": {"updated", "    if type(updated) != \"set\":\n        fail(\"configure requires a set\")\n", func(*scriptFixture) addon.Hook { return addon.ConfigureHook{Updated: map[string]struct{}{"test": {}}} }},
		"running":   {"", "", func(*scriptFixture) addon.Hook { return addon.RunningHook{} }},
		"done":      {"", "", func(*scriptFixture) addon.Hook { return addon.DoneHook{} }},
		"update":    {"flows", "    if len(flows) != 1:\n        fail(\"protected update flow sequence missing\")\n    flows[0].comment = \"updated\"\n", func(f *scriptFixture) addon.Hook { return addon.UpdateHook{Flows: []flow.Flow{f.request()}} }},
		"add_log":   {"entry", "    if entry.msg != \"probe\":\n        fail(\"log entry wrapper missing\")\n", func(*scriptFixture) addon.Hook { return addon.AddLogHook{Entry: addon.LogEntry{Msg: "probe"}} }},
		"next_layer": {"data", "    if data.data_client != b\"client\":\n        fail(\"next-layer bytes changed\")\n    data.layer = [\"tcp\"]\n", func(*scriptFixture) addon.Hook {
			return addon.NextLayerHook{Data: &hookdata.NextLayer{DataClient: []byte("client")}}
		}},
		"client_connected": {"conn", "    conn.error = \"refused\"\n", func(*scriptFixture) addon.Hook {
			return addon.ClientConnectedHook{Client: connection.NewClient(connection.Address{}, connection.Address{}, 0)}
		}},
		"client_disconnected": {"conn", "    if conn.id == \"\":\n        fail(\"client metadata missing\")\n", func(*scriptFixture) addon.Hook {
			return addon.ClientDisconnectedHook{Client: connection.NewClient(connection.Address{}, connection.Address{}, 0)}
		}},
		"server_connect": {"data", "    data.server.address = (\"example.test\", 8080)\n", func(*scriptFixture) addon.Hook {
			return addon.ServerConnectHook{Data: &hookdata.ServerConnection{Server: connection.NewServer(nil)}}
		}},
		"server_connected": {"data", "    data.server.error = \"probe\"\n", func(*scriptFixture) addon.Hook {
			return addon.ServerConnectedHook{Data: &hookdata.ServerConnection{Server: connection.NewServer(nil)}}
		}},
		"server_disconnected": {"data", "    data.server.error = \"probe\"\n", func(*scriptFixture) addon.Hook {
			return addon.ServerDisconnectedHook{Data: &hookdata.ServerConnection{Server: connection.NewServer(nil)}}
		}},
		"server_connect_error": {"data", "    data.server.error = \"probe\"\n", func(*scriptFixture) addon.Hook {
			return addon.ServerConnectErrorHook{Data: &hookdata.ServerConnection{Server: connection.NewServer(nil)}}
		}},
		"socks5_auth": {"data", "    data.valid = data.username == \"user\"\n", func(*scriptFixture) addon.Hook {
			return addon.Socks5AuthHook{Data: &hookdata.Socks5Auth{Username: "user"}}
		}},
		"requestheaders":         {"f", "    f.comment = f.type\n", func(f *scriptFixture) addon.Hook { return addon.RequestHeadersHook{Flow: f.request()} }},
		"request":                {"f", "    f.request.path = \"/hook\"\n", func(f *scriptFixture) addon.Hook { return addon.RequestHook{Flow: f.request()} }},
		"responseheaders":        {"f", "    f.comment = f.type\n", func(f *scriptFixture) addon.Hook { return addon.ResponseHeadersHook{Flow: f.request()} }},
		"response":               {"f", "    f.comment = f.type\n", func(f *scriptFixture) addon.Hook { return addon.ResponseHook{Flow: f.request()} }},
		"error":                  {"f", "    f.comment = f.type\n", func(f *scriptFixture) addon.Hook { return addon.ErrorHook{Flow: f.request()} }},
		"http_connect":           {"f", "    f.comment = f.type\n", func(f *scriptFixture) addon.Hook { return addon.HTTPConnectHook{Flow: f.request()} }},
		"http_connect_upstream":  {"f", "    f.comment = f.type\n", func(f *scriptFixture) addon.Hook { return addon.HTTPConnectUpstreamHook{Flow: f.request()} }},
		"http_connected":         {"f", "    f.comment = f.type\n", func(f *scriptFixture) addon.Hook { return addon.HTTPConnectedHook{Flow: f.request()} }},
		"http_connect_error":     {"f", "    f.comment = f.type\n", func(f *scriptFixture) addon.Hook { return addon.HTTPConnectErrorHook{Flow: f.request()} }},
		"websocket_start":        {"f", "    f.comment = f.type\n", func(f *scriptFixture) addon.Hook { return addon.WebSocketStartHook{Flow: f.request()} }},
		"websocket_message":      {"f", "    f.comment = f.type\n", func(f *scriptFixture) addon.Hook { return addon.WebSocketMessageHook{Flow: f.request()} }},
		"websocket_end":          {"f", "    f.comment = f.type\n", func(f *scriptFixture) addon.Hook { return addon.WebSocketEndHook{Flow: f.request()} }},
		"tcp_start":              {"f", "    f.comment = f.type\n", func(*scriptFixture) addon.Hook { return addon.TCPStartHook{Flow: flow.NewTCPFlow(nil, nil, true)} }},
		"tcp_message":            {"f", "    f.comment = f.type\n", func(*scriptFixture) addon.Hook { return addon.TCPMessageHook{Flow: flow.NewTCPFlow(nil, nil, true)} }},
		"tcp_end":                {"f", "    f.comment = f.type\n", func(*scriptFixture) addon.Hook { return addon.TCPEndHook{Flow: flow.NewTCPFlow(nil, nil, true)} }},
		"tcp_error":              {"f", "    f.comment = f.type\n", func(*scriptFixture) addon.Hook { return addon.TCPErrorHook{Flow: flow.NewTCPFlow(nil, nil, true)} }},
		"udp_start":              {"f", "    f.comment = f.type\n", func(*scriptFixture) addon.Hook { return addon.UDPStartHook{Flow: flow.NewUDPFlow(nil, nil, true)} }},
		"udp_message":            {"f", "    f.comment = f.type\n", func(*scriptFixture) addon.Hook { return addon.UDPMessageHook{Flow: flow.NewUDPFlow(nil, nil, true)} }},
		"udp_end":                {"f", "    f.comment = f.type\n", func(*scriptFixture) addon.Hook { return addon.UDPEndHook{Flow: flow.NewUDPFlow(nil, nil, true)} }},
		"udp_error":              {"f", "    f.comment = f.type\n", func(*scriptFixture) addon.Hook { return addon.UDPErrorHook{Flow: flow.NewUDPFlow(nil, nil, true)} }},
		"dns_request":            {"f", "    f.comment = f.type\n", func(*scriptFixture) addon.Hook { return addon.DNSRequestHook{Flow: flow.NewDNSFlow(nil, nil, true)} }},
		"dns_response":           {"f", "    f.comment = f.type\n", func(*scriptFixture) addon.Hook { return addon.DNSResponseHook{Flow: flow.NewDNSFlow(nil, nil, true)} }},
		"dns_error":              {"f", "    f.comment = f.type\n", func(*scriptFixture) addon.Hook { return addon.DNSErrorHook{Flow: flow.NewDNSFlow(nil, nil, true)} }},
		"tls_clienthello":        {"data", "    data.ignore_connection = True\n    data.establish_server_tls_first = True\n", func(*scriptFixture) addon.Hook { return addon.TLSClientHelloHook{Data: &hookdata.ClientHello{}} }},
		"tls_start_client":       {"data", "    if data.is_dtls:\n        fail(\"unexpected transport\")\n", func(*scriptFixture) addon.Hook { return addon.TLSStartClientHook{Data: &hookdata.TLS{}} }},
		"tls_start_server":       {"data", "    if data.is_dtls:\n        fail(\"unexpected transport\")\n", func(*scriptFixture) addon.Hook { return addon.TLSStartServerHook{Data: &hookdata.TLS{}} }},
		"tls_established_client": {"data", "    if data.is_dtls:\n        fail(\"unexpected transport\")\n", func(*scriptFixture) addon.Hook { return addon.TLSEstablishedClientHook{Data: &hookdata.TLS{}} }},
		"tls_established_server": {"data", "    if data.is_dtls:\n        fail(\"unexpected transport\")\n", func(*scriptFixture) addon.Hook { return addon.TLSEstablishedServerHook{Data: &hookdata.TLS{}} }},
		"tls_failed_client":      {"data", "    if data.is_dtls:\n        fail(\"unexpected transport\")\n", func(*scriptFixture) addon.Hook { return addon.TLSFailedClientHook{Data: &hookdata.TLS{}} }},
		"tls_failed_server":      {"data", "    if data.is_dtls:\n        fail(\"unexpected transport\")\n", func(*scriptFixture) addon.Hook { return addon.TLSFailedServerHook{Data: &hookdata.TLS{}} }},
		"quic_start_client":      {"data", "    if data.is_dtls:\n        fail(\"unexpected transport\")\n", func(*scriptFixture) addon.Hook { return addon.QUICStartClientHook{Data: &hookdata.QUICTLS{}} }},
		"quic_start_server":      {"data", "    if data.is_dtls:\n        fail(\"unexpected transport\")\n", func(*scriptFixture) addon.Hook { return addon.QUICStartServerHook{Data: &hookdata.QUICTLS{}} }},
	}
	t.Run("hooks", func(t *testing.T) {
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				f := newFixture(t)
				path := f.file("hook.star", fmt.Sprintf("state = {\"seen\": 0}\ndef %s(%s):\n%s    state[\"seen\"] += 1\n", name, test.argument, test.assertion))
				f.load(path)
				readCount := func() int {
					t.Helper()
					var count int
					if err := f.master.Do(t.Context(), func(context.Context) error {
						if len(f.loader.entries) != 1 || f.loader.entries[0].module == nil {
							return fmt.Errorf("hook load failed: %s", f.logs.String())
						}
						dict := f.loader.entries[0].module.members["state"].(*starlark.Dict)
						value, _, err := dict.Get(starlark.String("seen"))
						if err != nil {
							return err
						}
						count, err = intValue(value)
						return err
					}); err != nil {
						t.Fatal(err)
					}
					return count
				}
				before := readCount()
				if test.hook == nil {
					if before != 1 || !f.master.Options.Bool("hook_loaded") {
						t.Fatal("on_load did not receive a usable Loader")
					}
					return
				}
				f.hook(test.hook(f))
				if got := readCount(); got != before+1 {
					t.Fatalf("%s invocation count=%d want=%d; records=%s", name, got, before+1, f.logs.String())
				}
				f.wantLog("Addon error:", 0)
			})
		}
	})
}
