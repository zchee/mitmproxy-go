// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package nextlayer

import (
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
)

func TestSniffParserLifecycle(t *testing.T) {
	tests := map[string]struct{ finish string }{
		"success: completed hello releases parser":        {finish: "complete"},
		"success: disconnect releases parser":             {finish: "disconnect"},
		"success: fallback releases parser":               {finish: "fallback"},
		"success: another addon decision releases parser": {finish: "decided"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, manager, _ := testAddon(t, map[string]any{"ignore_hosts": []string{"example.com"}})
			wire := hello(t, helloSNI)
			first := &hookdata.NextLayer{Context: testContext(a.opts, "192.0.2.1", "transparent"), DataClient: wire[:3]}
			second := &hookdata.NextLayer{Context: testContext(a.opts, "192.0.2.2", "transparent"), DataClient: wire[:9]}
			for _, d := range []*hookdata.NextLayer{first, second} {
				if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
					t.Fatal(err)
				}
				if d.Layer != nil {
					t.Fatalf("incomplete hello selected %v", d.Layer)
				}
			}
			parser := a.hellos[first.Context.Client]
			if len(a.hellos) != 2 || parser == nil || parser == a.hellos[second.Context.Client] {
				t.Fatalf("parsers are not independent: %v", a.hellos)
			}
			if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: first}); err != nil || a.hellos[first.Context.Client] != parser {
				t.Fatalf("repeated prefix discarded parser: %v", err)
			}
			switch tt.finish {
			case "complete":
				first.DataClient = wire
			case "fallback":
				first.DataClient = make([]byte, sniffLimit)
				copy(first.DataClient, wire)
			case "decided":
				first.Layer = hookdata.LayerStack{{Kind: hookdata.LayerTCP}}
			case "disconnect":
				if err := manager.Hook(t.Context(), addon.ClientDisconnectedHook{Client: first.Context.Client}); err != nil {
					t.Fatal(err)
				}
			}
			if tt.finish != "disconnect" {
				if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: first}); err != nil {
					t.Fatal(err)
				}
			}
			if len(a.hellos) != 1 || a.hellos[first.Context.Client] != nil || a.hellos[second.Context.Client] == nil {
				t.Fatalf("completion retained parser or discarded another client: %v", a.hellos)
			}
			if err := manager.Hook(t.Context(), addon.ClientDisconnectedHook{Client: second.Context.Client}); err != nil {
				t.Fatal(err)
			}
			if len(a.hellos) != 0 {
				t.Fatalf("disconnect retained %d parsers", len(a.hellos))
			}
		})
	}
}
