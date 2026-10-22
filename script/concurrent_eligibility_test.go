// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"fmt"
	"strings"
	"testing"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

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
					for _, child := range []bool{false, true} {
						predeclared := starlark.StringDict{"concurrent": starlark.NewBuiltin("concurrent", concurrentBuiltin), "module": starlark.NewBuiltin("module", starlarkstruct.MakeModule)}
						source := "def _not_the_hook(f):\n    pass\n"
						if child {
							source += fmt.Sprintf("addons = [module('child', %s=concurrent(_not_the_hook))]\n", name)
						} else {
							source += fmt.Sprintf("%s = concurrent(_not_the_hook)\n", name)
						}
						_, program, err := starlark.SourceProgramOptions(&syntax.FileOptions{}, "eligibility.star", source, predeclared.Has)
						if err != nil {
							t.Fatal(err)
						}
						globals, err := program.Init(&starlark.Thread{}, predeclared)
						if err != nil {
							t.Fatal(err)
						}
						live, count, err := discoverConcurrent(globals, nil)
						if !test.accepted {
							want := fmt.Sprintf("Concurrent decorator not supported for '%s' method.", name)
							if err == nil || !strings.Contains(err.Error(), want) {
								t.Fatalf("binding %s child=%v: %v", name, child, err)
							}
							continue
						}
						if err != nil || count != 1 {
							t.Fatalf("accepted binding %s child=%v count=%d: %v", name, child, count, err)
						}
						frozenGlobals, err := program.Init(&starlark.Thread{}, predeclared)
						if err != nil {
							t.Fatal(err)
						}
						frozen, _, err := discoverConcurrent(frozenGlobals, nil)
						if err != nil {
							t.Fatal(err)
						}
						if err := live.corresponds(frozen, false); err != nil {
							t.Fatal(err)
						}
						if err := live.corresponds(live, true); err != nil {
							t.Fatal(err)
						}
						if err := live.corresponds(frozen, true); err == nil {
							t.Fatal("changed wrapper identity accepted as live path")
						}
						frozenGlobals.Freeze()
						node := frozen
						if child {
							node = frozen.children[0]
						}
						wrapper := node.wrappers[name]
						if wrapper.function.Name() != "_not_the_hook" {
							t.Fatal("eligibility used def name instead of binding")
						}
						_, err = starlark.Call(&starlark.Thread{}, wrapper, starlark.Tuple{starlark.None}, nil)
						if err == nil || !strings.Contains(err.Error(), "concurrent(_not_the_hook) cannot be called directly; it runs only when invoked as a hook") {
							t.Fatalf("direct wrapper call: %v", err)
						}
					}
				})
			}
		})
	}
}
