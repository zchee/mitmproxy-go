// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package nextlayer

import (
	"context"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
)

func TestPacketHostMatchAbandonment(t *testing.T) {
	tests := map[string]struct {
		option string
		ignore bool
	}{
		"ignore abandonment ignores":                {option: "ignore_hosts", ignore: true},
		"allow abandonment does not allow":          {option: "allow_hosts", ignore: true},
		"udp abandonment does not force a decision": {option: "udp_hosts"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			pattern := "(?=a)(a+)+$"
			host := strings.Repeat("a", 1000) + "!"
			a, manager, logs := testAddon(t, map[string]any{test.option: []string{pattern}})
			a.matchTimeout = time.Nanosecond
			c := testContext(a.opts, host, "transparent")
			c.Client.TransportProtocol, c.Server.TransportProtocol = connection.UDP, connection.UDP
			d := &hookdata.NextLayer{Context: c, DataClient: []byte{0xff}}
			if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(hookdata.LayerStack{{Kind: hookdata.LayerUDP, Ignore: test.ignore}}, d.Layer); diff != "" {
				t.Fatal(diff)
			}
			for _, text := range []string{"abandoned", pattern, host, test.option} {
				if !strings.Contains(logs.String(), text) {
					t.Fatalf("log missing %q: %s", text, logs.String())
				}
			}
		})
	}
}

func TestPacketHostPatternRollback(t *testing.T) {
	tests := map[string]struct{ pattern string }{
		"unclosed character class": {pattern: "["},
		"unclosed group":           {pattern: "("},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			a, manager, _ := testAddon(t, map[string]any{"udp_hosts": []string{"example.com"}})
			if err := manager.Do(t.Context(), func(ctx context.Context) error {
				return a.opts.Update(ctx, map[string]any{"udp_hosts": []string{test.pattern}})
			}); err == nil {
				t.Fatal("invalid UDP pattern accepted")
			}
			if err := manager.Do(t.Context(), func(context.Context) error {
				if diff := gocmp.Diff([]string{"example.com"}, a.opts.Seq("udp_hosts")); diff != "" {
					t.Error(diff)
				}
				if len(a.hosts["udp_hosts"]) != 1 || a.hosts["udp_hosts"][0].Pattern() != "example.com" {
					t.Error("failed configure replaced compiled UDP patterns")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
