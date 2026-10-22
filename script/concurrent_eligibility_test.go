// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
)

func concurrentTestHook(name string, f flow.Flow) addon.Hook {
	switch name {
	case "requestheaders":
		return addon.RequestHeadersHook{Flow: f.(*flow.HTTPFlow)}
	case "request":
		return addon.RequestHook{Flow: f.(*flow.HTTPFlow)}
	case "responseheaders":
		return addon.ResponseHeadersHook{Flow: f.(*flow.HTTPFlow)}
	case "response":
		return addon.ResponseHook{Flow: f.(*flow.HTTPFlow)}
	case "error":
		return addon.ErrorHook{Flow: f.(*flow.HTTPFlow)}
	case "http_connect":
		return addon.HTTPConnectHook{Flow: f.(*flow.HTTPFlow)}
	case "http_connect_upstream":
		return addon.HTTPConnectUpstreamHook{Flow: f.(*flow.HTTPFlow)}
	case "http_connected":
		return addon.HTTPConnectedHook{Flow: f.(*flow.HTTPFlow)}
	case "http_connect_error":
		return addon.HTTPConnectErrorHook{Flow: f.(*flow.HTTPFlow)}
	case "websocket_start":
		return addon.WebSocketStartHook{Flow: f.(*flow.HTTPFlow)}
	case "websocket_message":
		return addon.WebSocketMessageHook{Flow: f.(*flow.HTTPFlow)}
	case "websocket_end":
		return addon.WebSocketEndHook{Flow: f.(*flow.HTTPFlow)}
	case "tcp_start":
		return addon.TCPStartHook{Flow: f.(*flow.TCPFlow)}
	case "tcp_message":
		return addon.TCPMessageHook{Flow: f.(*flow.TCPFlow)}
	case "tcp_end":
		return addon.TCPEndHook{Flow: f.(*flow.TCPFlow)}
	case "tcp_error":
		return addon.TCPErrorHook{Flow: f.(*flow.TCPFlow)}
	case "udp_start":
		return addon.UDPStartHook{Flow: f.(*flow.UDPFlow)}
	case "udp_message":
		return addon.UDPMessageHook{Flow: f.(*flow.UDPFlow)}
	case "udp_end":
		return addon.UDPEndHook{Flow: f.(*flow.UDPFlow)}
	case "udp_error":
		return addon.UDPErrorHook{Flow: f.(*flow.UDPFlow)}
	case "dns_request":
		return addon.DNSRequestHook{Flow: f.(*flow.DNSFlow)}
	case "dns_response":
		return addon.DNSResponseHook{Flow: f.(*flow.DNSFlow)}
	case "dns_error":
		return addon.DNSErrorHook{Flow: f.(*flow.DNSFlow)}
	default:
		panic("unrecognized test hook: " + name)
	}
}

func TestScriptConcurrentEligibility(t *testing.T) {
	tests := map[string]struct{ accepted bool }{
		"requestheaders": {true}, "request": {true}, "responseheaders": {true}, "response": {true}, "error": {true},
		"http_connect": {true}, "http_connect_upstream": {true}, "http_connected": {true}, "http_connect_error": {true},
		"websocket_start": {true}, "websocket_message": {true}, "websocket_end": {true},
		"tcp_start": {true}, "tcp_message": {true}, "tcp_end": {true}, "tcp_error": {true},
		"udp_start": {true}, "udp_message": {true}, "udp_end": {true}, "udp_error": {true},
		"dns_request": {true}, "dns_response": {true}, "dns_error": {true},
		"on_load": {}, "configure": {}, "running": {}, "done": {}, "update": {}, "add_log": {}, "next_layer": {},
		"client_connected": {}, "client_disconnected": {}, "server_connect": {}, "server_connected": {}, "server_disconnected": {}, "server_connect_error": {}, "socks5_auth": {},
		"tls_clienthello": {}, "tls_start_client": {}, "tls_start_server": {}, "tls_established_client": {}, "tls_established_server": {}, "tls_failed_client": {}, "tls_failed_server": {}, "quic_start_client": {}, "quic_start_server": {}, "helper": {},
	}
	for _, accepted := range []bool{true, false} {
		group := "rejected"
		if accepted {
			group = "accepted"
		}
		t.Run(group, func(t *testing.T) {
			for name, test := range tests {
				if test.accepted != accepted {
					continue
				}
				t.Run(name, func(t *testing.T) {
					f := newFixture(t)
					f.load(f.file("eligibility.star", fmt.Sprintf("def _not_the_hook(f):\n    f.comment = %q\n%s = concurrent(_not_the_hook)\n", name, name)))
					if !test.accepted {
						f.wantLog(fmt.Sprintf("Concurrent decorator not supported for '%s' method.", name), 1)
						if f.loader.entries[0].module != nil {
							t.Fatal("invalid binding registered")
						}
						return
					}
					var model flow.Flow = f.request()
					switch {
					case strings.HasPrefix(name, "tcp_"):
						model = flow.NewTCPFlow(model.Common().ClientConn, model.Common().ServerConn, true)
					case strings.HasPrefix(name, "udp_"):
						model = flow.NewUDPFlow(model.Common().ClientConn, model.Common().ServerConn, true)
					case strings.HasPrefix(name, "dns_"):
						d := flow.NewDNSFlow(model.Common().ClientConn, model.Common().ServerConn, true)
						d.Request = &dns.Message{Query: true, Questions: []dns.Question{{Name: "example.test", Type: dns.TypeA, Class: dns.ClassIN}}}
						model = d
					}
					f.hook(concurrentTestHook(name, model))
					if model.Common().Comment != name {
						t.Fatalf("hook did not run/merge: %q; logs=%s", model.Common().Comment, f.logs.String())
					}
					f.wantLog("Addon error:", 0)
					if err := f.master.Do(t.Context(), func(context.Context) error {
						module := f.loader.entries[0].module
						if module == nil || module.concurrent == nil || !module.concurrent.graph.worker {
							return fmt.Errorf("missing frozen worker instance")
						}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
					if name == "dns_response" {
						connections := map[string]struct{ client, server bool }{
							"both": {true, true}, "client": {true, false}, "server": {false, true}, "neither": {},
						}
						for _, hook := range []string{"dns_request", "dns_response", "dns_error"} {
							for label, presence := range connections {
								probe := newFixture(t)
								body := fmt.Sprintf("def _dns(f):\n    if f.request != None or (f.client_conn != None) != %s or (f.server_conn != None) != %s:\n        fail('absent fields became visible')\n    if f.modified():\n        fail('unbacked clone is modified')\n    f.revert()\n    if f.request != None:\n        fail('revert introduced a request')\n    f.response.id = 7\n    f.comment = 'requestless-completed'\n%s = concurrent(_dns)\n", map[bool]string{true: "True", false: "False"}[presence.client], map[bool]string{true: "True", false: "False"}[presence.server], hook)
								probe.load(probe.file("requestless.star", body))
								h := probe.request()
								d := flow.NewDNSFlow(h.ClientConn, h.ServerConn, true)
								if !presence.client {
									d.ClientConn = nil
								}
								if !presence.server {
									d.ServerConn = nil
								}
								d.Response = &dns.Message{ID: 1}
								id := d.ID
								probe.hook(concurrentTestHook(hook, d))
								if d.Request != nil || d.ID != id || !d.Live || d.Response.ID != 7 || d.Comment != "requestless-completed" || (d.ClientConn != nil) != presence.client || (d.ServerConn != nil) != presence.server || d.Modified() {
									t.Fatalf("requestless %s/%s failed: flow=%+v logs=%s", hook, label, d, probe.logs.String())
								}
								probe.wantLog("Addon error:", 0)
							}
						}
					}
				})
			}
		})
	}
}
