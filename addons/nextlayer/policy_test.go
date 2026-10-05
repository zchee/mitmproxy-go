// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package nextlayer

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
)

func TestBoundedSniffing(t *testing.T) {
	tests := map[string]struct{ client, server []byte }{
		"error: HTTP header at limit":     {client: []byte("GET / HTTP/1.1" + strings.Repeat("x", (64<<10)-13))},
		"error: non HTTP line at limit":   {client: bytes.Repeat([]byte{'A'}, 64<<10)},
		"error: client beyond limit":      {client: bytes.Repeat([]byte{'A'}, (64<<10)+1)},
		"error: declared oversized hello": {client: []byte{0x16, 0x03, 0x03, 0xff, 0xff, 0x01, 0x01, 0x00, 0x00}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, manager, logs := testAddon(t, map[string]any{"ignore_hosts": []string{"example.com"}, "rawtcp": false})
			d := &hookdata.NextLayer{Context: testContext(a.opts, "example.com", "transparent"), DataClient: tt.client, DataServer: tt.server}
			if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
				t.Fatal(err)
			}
			want := hookdata.LayerStack{{Kind: hookdata.LayerTCP}}
			if diff := gocmp.Diff(want, d.Layer); diff != "" {
				t.Errorf("bounded fallback (-want +got):\n%s", diff)
			}
			if !strings.Contains(logs.String(), "sniff limit") {
				t.Errorf("missing fallback reason: %s", logs)
			}
			if lines := strings.Count(logs.String(), "\n"); lines != 1 {
				t.Errorf("got %d log records, want 1: %s", lines, logs)
			}
		})
	}
}

func TestIncrementalSniffing(t *testing.T) {
	tests := map[string]struct {
		data  []byte
		start int
	}{
		"success: TLS every incomplete prefix":  {data: hello(t, helloSNI), start: 3},
		"success: HTTP every incomplete prefix": {data: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n"), start: len("GET / HTTP/")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, manager, logs := testAddon(t, map[string]any{"ignore_hosts": []string{"example.com"}})
			d := &hookdata.NextLayer{Context: testContext(a.opts, "example.com", "transparent")}
			for n := tt.start; n < len(tt.data); n++ {
				d.DataClient = tt.data[:n]
				if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
					t.Fatal(err)
				}
				if d.Layer != nil {
					t.Fatalf("prefix %d/%d chose %#v", n, len(tt.data), d.Layer)
				}
			}
			if !strings.Contains(logs.String(), "Deferring layer decision") {
				t.Error("missing deferral log")
			}
			d.DataClient = tt.data
			if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(hookdata.LayerStack{{Kind: hookdata.LayerTCP, Ignore: true}}, d.Layer); diff != "" {
				t.Errorf("complete decision (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAbandonedHostMatch(t *testing.T) {
	tests := map[string]struct {
		option string
		want   hookdata.LayerStack
	}{
		"success: ignore abandonment ignores":         {option: "ignore_hosts", want: hookdata.LayerStack{{Kind: hookdata.LayerTCP, Ignore: true}}},
		"success: allow abandonment does not allow":   {option: "allow_hosts", want: hookdata.LayerStack{{Kind: hookdata.LayerTCP, Ignore: true}}},
		"success: tcp abandonment does not force tcp": {option: "tcp_hosts", want: hookdata.LayerStack{{Kind: hookdata.LayerHTTP, HTTPMode: hookdata.HTTPModeTransparent}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pattern := "(?=a)(a+)+$"
			host := strings.Repeat("a", 1000) + "!"
			a, manager, logs := testAddon(t, map[string]any{tt.option: []string{pattern}})
			a.matchTimeout = time.Nanosecond
			d := &hookdata.NextLayer{Context: testContext(a.opts, host, "transparent"), DataClient: []byte("GET / HTTP/1.1\r\n\r\n")}
			if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, d.Layer); diff != "" {
				t.Errorf("abandoned policy (-want +got):\n%s", diff)
			}
			for _, text := range []string{"abandoned", pattern, host, tt.option} {
				if !strings.Contains(logs.String(), text) {
					t.Errorf("log missing %q: %s", text, logs)
				}
			}
			if lines := strings.Count(logs.String(), "\n"); lines != 1 {
				t.Errorf("got %d log records, want 1: %s", lines, logs)
			}
		})
	}
}

func TestDecisionPrecedence(t *testing.T) {
	tests := map[string]struct {
		values                        map[string]any
		data, server, sni, alpn, mode string
		before                        []hookdata.LayerKind
		initial, want                 hookdata.LayerStack
	}{
		"success: preserve existing decision":               {initial: hookdata.LayerStack{{Kind: hookdata.LayerHTTP, HTTPMode: hookdata.HTTPModeUpstream}}, data: strings.Repeat("a", 64<<10), want: hookdata.LayerStack{{Kind: hookdata.LayerHTTP, HTTPMode: hookdata.HTTPModeUpstream}}},
		"success: show ignored hosts":                       {values: map[string]any{"ignore_hosts": []string{"example.com"}, "show_ignored_hosts": true}, data: httpGet, want: hookdata.LayerStack{{Kind: hookdata.LayerTCP}}},
		"success: rawtcp disabled":                          {values: map[string]any{"rawtcp": false}, data: "not http", want: hookdata.LayerStack{{Kind: hookdata.LayerHTTP, HTTPMode: hookdata.HTTPModeTransparent}}},
		"success: tcp hosts before ALPN":                    {values: map[string]any{"tcp_hosts": []string{"(?=EXAMPLE)EXAMPLE"}}, alpn: "h2", data: httpGet, want: hookdata.LayerStack{{Kind: hookdata.LayerTCP}}},
		"success: tcp hosts use SNI without port":           {values: map[string]any{"tcp_hosts": []string{"^SNI\\.example$"}}, sni: "sni.example", data: httpGet, want: hookdata.LayerStack{{Kind: hookdata.LayerTCP}}},
		"success: ignore hosts before reverse":              {values: map[string]any{"ignore_hosts": []string{"(?=EXAMPLE)EXAMPLE"}}, mode: "reverse:https://example.com", before: []hookdata.LayerKind{hookdata.LayerReverse}, data: httpGet, want: hookdata.LayerStack{{Kind: hookdata.LayerTCP, Ignore: true}}},
		"success: reverse TCP preserves HTTP-looking bytes": {mode: "reverse:tcp://example.com:443", before: []hookdata.LayerKind{hookdata.LayerReverse}, data: httpGet, want: hookdata.LayerStack{{Kind: hookdata.LayerTCP}}},
		"success: reverse TLS preserves HTTP-looking bytes": {mode: "reverse:tls://example.com:443", before: []hookdata.LayerKind{hookdata.LayerReverse}, data: httpGet, want: hookdata.LayerStack{{Kind: hookdata.LayerServerTLS}, {Kind: hookdata.LayerTCP}}},
		"success: no newline follows upstream heuristic":    {data: "GET / HTTP/1.1", want: hookdata.LayerStack{{Kind: hookdata.LayerTCP}}},
		"success: server greeting prevents HTTP host sniff": {values: map[string]any{"ignore_hosts": []string{"absent"}}, data: "GET / HTTP/1.1", server: "220 hello", want: hookdata.LayerStack{{Kind: hookdata.LayerTCP}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, manager, _ := testAddon(t, tt.values)
			before := tt.before
			if before == nil {
				before = []hookdata.LayerKind{"transparent"}
			}
			c := testContext(a.opts, "example.com", before...)
			if tt.sni != "" {
				c.Client.SNI = &tt.sni
			}
			if tt.mode != "" {
				c.Client.ProxyMode = tt.mode
			}
			c.Client.ALPN = []byte(tt.alpn)
			d := &hookdata.NextLayer{Context: c, DataClient: []byte(tt.data), DataServer: []byte(tt.server), Layer: tt.initial}
			if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, d.Layer); diff != "" {
				t.Errorf("decision (-want +got):\n%s", diff)
			}
		})
	}
}

func TestConfigureRollbackAndConcurrentDispatch(t *testing.T) {
	a, manager, _ := testAddon(t, map[string]any{"tcp_hosts": []string{"example.com"}})
	if err := manager.Do(t.Context(), func(ctx context.Context) error {
		return a.opts.Update(ctx, map[string]any{"tcp_hosts": []string{"other"}, "ignore_hosts": []string{"["}})
	}); err == nil {
		t.Fatal("invalid pattern accepted")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 16 {
				d := &hookdata.NextLayer{Context: testContext(a.opts, "example.com", "transparent"), DataClient: []byte(httpGet)}
				if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
					t.Error(err)
					return
				}
				if diff := gocmp.Diff(hookdata.LayerStack{{Kind: hookdata.LayerTCP}}, d.Layer); diff != "" {
					t.Errorf("rollback decision (-want +got):\n%s", diff)
				}
			}
		})
	}
	wg.Wait()
}

func FuzzNextLayer(f *testing.F) {
	for _, seed := range [][]byte{[]byte(httpGet), {0x16, 0x03, 0x03}, {0xff}, []byte("SSH-2.0")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > (64<<10)+1 {
			return
		}
		a, manager, _ := testAddon(t, map[string]any{"ignore_hosts": []string{"example.com"}})
		d := &hookdata.NextLayer{Context: testContext(a.opts, "example.org", "transparent"), DataClient: data}
		if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
			t.Fatal(err)
		}
		if len(d.Layer) > 2 {
			t.Fatalf("unexpected generic stack: %#v", d.Layer)
		}
	})
}
