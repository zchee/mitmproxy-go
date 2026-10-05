// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package nextlayer

import (
	"bytes"
	"context"
	"encoding/hex"
	json "encoding/json/v2"
	"log/slog"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/options"
)

const (
	httpGet     = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	httpConnect = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	helloPlain  = "16030300650100006103015658a756ab2c2bff55f636814deac086b7ca56b65058c7893ffc6074f5245f70205658a75475103a15263778e1bb6d22e8bbd5b6b0a3a59760ad354e91ba20d353001a0035002f000a00050004000900030006000800600061006200640100"
	helloSNI    = "16030300bb010000b703033b70638d2523e1cba15f8364868295305e9c52aceabda4b5147210abc783e6e1000022c02bc02fc02cc030cca9cca8cc14cc13c009c013c00ac014009c009d002f0035000a0100006cff0100010000000010000e00000b6578616d706c652e636f6d0017000000230000000d0012001006010603050105030401040302010203000500050100000000001200000010000e000c02683208687474702f312e3175500000000b00020100000a00080006001d00170018"
)

// Deferred upstream cases (test_next_layer.py):
// Test group              | Case names                              | Required protocol
// test_ignore_connection  | dtls sni; incomplete dtls client hello; invalid dtls client hello | DTLS
// test_ignore_connection  | quic sni; invalid quic; fragmented quic hello | QUIC
// test_next_layer         | explicit proxy: experimental http3       | QUIC
// test_next_layer         | reverse proxy: udp -> udp; reverse proxy: dtls -> dtls; reverse proxy: dtls -> udp; reverse proxy: udp -> dtls | UDP/DTLS
// test_next_layer         | reverse proxy: dns                       | DNS
// test_next_layer         | reverse proxy: http3; reverse proxy: http3 in https mode; reverse proxy: quic | QUIC
// test_next_layer         | transparent proxy: dtls                  | DTLS
// test_next_layer         | transparent proxy: quic; transparent proxy: existing quic session; transparent proxy: http3 via ALPN | QUIC
// test_next_layer         | transparent proxy: raw udp; transparent proxy: udp_hosts | UDP
// test_next_layer         | transparent proxy: dns over udp; transparent proxy: dns over tcp; wireguard proxy: dns should not be ignored | DNS
// test_next_layer         | transparent proxy: non-http quic; transparent proxy: http3 not ignored but with ignoring active | QUIC
// test_starts_like_quic   | all assertions                           | QUIC

type layerKind hookdata.LayerKind

func (k layerKind) Kind() hookdata.LayerKind { return hookdata.LayerKind(k) }

func testAddon(t *testing.T, values map[string]any) (*NextLayer, *addon.Manager, *bytes.Buffer) {
	t.Helper()
	opts := options.New()
	a := New(opts)
	var logs bytes.Buffer
	a.logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	manager := addon.NewManager(opts, command.NewManager(), addon.Config{Logger: a.logger})
	t.Cleanup(manager.Close)
	if err := manager.Add(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if err := manager.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, values) }); err != nil {
		t.Fatal(err)
	}
	return a, manager, &logs
}

func testContext(opts *options.Manager, host string, kinds ...hookdata.LayerKind) *hookdata.Context {
	c := &hookdata.Context{
		Client:  &connection.Client{TransportProtocol: connection.TCP, ProxyMode: "regular"},
		Server:  &connection.Server{TransportProtocol: connection.TCP},
		Options: opts,
	}
	if host != "" {
		c.Server.Address = &connection.Address{Host: host, Port: 443}
	}
	for _, kind := range kinds {
		c.Layers = append(c.Layers, layerKind(kind))
	}
	return c
}

func hello(t *testing.T, text string) []byte {
	t.Helper()
	b, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIgnoreConnectionUpstream(t *testing.T) {
	withSNI, withoutSNI := hello(t, helloSNI), hello(t, helloPlain)
	tests := map[string]struct {
		ignore, allow          []string
		host                   string
		data                   []byte
		ignored, deferDecision bool
	}{
		"nothing ignored":                       {host: "example.com"},
		"address":                               {ignore: []string{"example.com"}, host: "example.com", ignored: true},
		"ip address":                            {ignore: []string{"192.0.2.1"}, host: "example.com", ignored: true},
		"ipv6 address":                          {ignore: []string{"2001:db8::1"}, host: "ipv6.example.com", ignored: true},
		"port matches":                          {ignore: []string{"example.com:443"}, host: "example.com", ignored: true},
		"port does not match":                   {ignore: []string{"example.com:123"}, host: "example.com"},
		"http host header":                      {ignore: []string{"example.com"}, host: "192.0.2.1", data: []byte(httpGet), ignored: true},
		"http host header missing":              {ignore: []string{"example.com"}, host: "192.0.2.1", data: []byte(strings.ReplaceAll(httpGet, "Host", "X-Host"))},
		"incomplete http host header":           {ignore: []string{"example.com"}, host: "192.0.2.1", data: []byte("GET / HTTP/1.1"), deferDecision: true},
		"partial address match":                 {ignore: []string{"example.com"}, host: "com"},
		"no destination info":                   {ignore: []string{"example.com"}},
		"no sni":                                {ignore: []string{"example.com"}, data: withoutSNI},
		"sni":                                   {ignore: []string{"example.com"}, host: "192.0.2.1", data: withSNI, ignored: true},
		"incomplete client hello":               {ignore: []string{"example.com"}, host: "192.0.2.1", data: withSNI[:len(withSNI)-5], deferDecision: true},
		"invalid client hello":                  {ignore: []string{"example.com"}, host: "192.0.2.1", data: append(bytes.Clone(withoutSNI[:9]), make([]byte, 200)...)},
		"sni mismatch":                          {ignore: []string{"example.com"}, host: "decoy", data: withSNI, ignored: true},
		"allow: allow":                          {allow: []string{"example.com"}, host: "example.com"},
		"allow: ignore":                         {allow: []string{"example.com"}, host: "example.org", ignored: true},
		"allow: sni":                            {allow: []string{"example.com"}, host: "192.0.2.1", data: withSNI},
		"allow: sni from parent layer":          {allow: []string{"existing-sni.example"}, host: "192.0.2.1"},
		"allow: sni mismatch":                   {allow: []string{"example.com"}, host: "decoy", data: withSNI},
		"allow+ignore: allowed and not ignored": {ignore: []string{"binary.example.com"}, allow: []string{"example.com"}, host: "example.com"},
		"allow+ignore: allowed but ignored":     {ignore: []string{"binary.example.com"}, allow: []string{"example.com"}, host: "binary.example.org", ignored: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, manager, _ := testAddon(t, map[string]any{"ignore_hosts": tt.ignore, "allow_hosts": tt.allow})
			c := testContext(a.opts, tt.host, "transparent")
			c.Client.SNI = new("existing-sni.example")
			if tt.host != "" {
				peer := "192.0.2.1"
				if strings.HasPrefix(tt.host, "ipv6") {
					peer = "2001:db8::1"
				}
				c.Server.Peername = &connection.Address{Host: peer, Port: 443}
			}
			d := &hookdata.NextLayer{Context: c, DataClient: tt.data}
			if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
				t.Fatal(err)
			}
			if tt.deferDecision {
				if d.Layer != nil {
					t.Fatalf("incomplete input chose %#v", d.Layer)
				}
				return
			}
			if d.Layer == nil {
				t.Fatal("complete input deferred")
			}
			got := d.Layer[0].Kind == hookdata.LayerTCP && d.Layer[0].Ignore
			if diff := gocmp.Diff(tt.ignored, got); diff != "" {
				t.Errorf("ignore mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNextLayerUpstream(t *testing.T) {
	regular, upstream, reverse := hookdata.LayerRegular, hookdata.LayerUpstream, hookdata.LayerReverse
	clientTLS, serverTLS := hookdata.LayerClientTLS, hookdata.LayerServerTLS
	http, tcp := hookdata.LayerHTTP, hookdata.LayerTCP
	transparent := hookdata.LayerKind("transparent")
	regularHTTP := hookdata.LayerSpec{Kind: http, HTTPMode: hookdata.HTTPModeRegular}
	transparentHTTP := hookdata.LayerSpec{Kind: http, HTTPMode: hookdata.HTTPModeTransparent}
	plain, encrypted := hello(t, helloPlain), hello(t, helloSNI)
	tests := map[string]struct {
		before           []hookdata.LayerKind
		mode, host, alpn string
		client, server   []byte
		ignore, tcpHosts []string
		want             hookdata.LayerStack
	}{
		"explicit proxy: regular http connect":                            {before: []hookdata.LayerKind{regular}, client: []byte(httpConnect), want: hookdata.LayerStack{regularHTTP}},
		"explicit proxy: regular http connect disregards ignore_hosts":    {before: []hookdata.LayerKind{regular}, client: []byte(httpConnect), ignore: []string{".+"}, want: hookdata.LayerStack{regularHTTP}},
		"explicit proxy: HTTP over regular proxy disregards ignore_hosts": {before: []hookdata.LayerKind{regular}, client: []byte("GET http://example.com/ HTTP/1.1\r\n\r\n"), ignore: []string{".+"}, want: hookdata.LayerStack{regularHTTP}},
		"explicit proxy: secure web proxy":                                {before: []hookdata.LayerKind{regular}, client: plain, want: hookdata.LayerStack{{Kind: clientTLS}, regularHTTP}},
		"explicit proxy: ignore_hosts over established secure web proxy":  {before: []hookdata.LayerKind{regular, clientTLS, http, "httpstream"}, host: "192.0.2.1", ignore: []string{".+"}, client: encrypted, alpn: "http/1.1", want: hookdata.LayerStack{{Kind: tcp, Ignore: true}}},
		"explicit proxy: upstream proxy":                                  {before: []hookdata.LayerKind{upstream}, want: hookdata.LayerStack{{Kind: http, HTTPMode: hookdata.HTTPModeUpstream}}},
		"explicit proxy: HTTP over regular proxy":                         {before: []hookdata.LayerKind{regular, http, "httpstream"}, client: []byte("GET / HTTP/1.1\r\n"), want: hookdata.LayerStack{transparentHTTP}},
		"explicit proxy: TLS over regular proxy":                          {before: []hookdata.LayerKind{regular, http, "httpstream"}, client: encrypted, want: hookdata.LayerStack{{Kind: serverTLS}, {Kind: clientTLS}}},
		"explicit proxy: HTTPS over regular proxy":                        {before: []hookdata.LayerKind{regular, http, "httpstream", serverTLS, clientTLS}, client: []byte("GET / HTTP/1.1\r\n"), want: hookdata.LayerStack{transparentHTTP}},
		"explicit proxy: TCP over regular proxy":                          {before: []hookdata.LayerKind{regular, http, "httpstream"}, client: []byte{0xff}, want: hookdata.LayerStack{{Kind: tcp}}},
		"reverse proxy: tcp -> tcp":                                       {before: []hookdata.LayerKind{reverse}, mode: "reverse:tcp://example.com:42", want: hookdata.LayerStack{{Kind: tcp}}},
		"reverse proxy: tls -> tls":                                       {before: []hookdata.LayerKind{reverse}, mode: "reverse:tls://example.com:42", client: encrypted, want: hookdata.LayerStack{{Kind: serverTLS}, {Kind: clientTLS}, {Kind: tcp}}},
		"reverse proxy: tls -> tcp":                                       {before: []hookdata.LayerKind{reverse}, mode: "reverse:tcp://example.com:42", client: encrypted, want: hookdata.LayerStack{{Kind: clientTLS}, {Kind: tcp}}},
		"reverse proxy: tcp -> tls":                                       {before: []hookdata.LayerKind{reverse}, mode: "reverse:tls://example.com:42", want: hookdata.LayerStack{{Kind: serverTLS}, {Kind: tcp}}},
		"reverse proxy: http -> http":                                     {before: []hookdata.LayerKind{reverse}, mode: "reverse:http://example.com:42", want: hookdata.LayerStack{transparentHTTP}},
		"reverse proxy: https -> https":                                   {before: []hookdata.LayerKind{reverse}, mode: "reverse:https://example.com:42", client: encrypted, want: hookdata.LayerStack{{Kind: serverTLS}, {Kind: clientTLS}, transparentHTTP}},
		"reverse proxy: https -> http":                                    {before: []hookdata.LayerKind{reverse}, mode: "reverse:http://example.com:42", client: encrypted, want: hookdata.LayerStack{{Kind: clientTLS}, transparentHTTP}},
		"reverse proxy: http -> https":                                    {before: []hookdata.LayerKind{reverse}, mode: "reverse:https://example.com:42", want: hookdata.LayerStack{{Kind: serverTLS}, transparentHTTP}},
		"reverse proxy: ignore_hosts":                                     {before: []hookdata.LayerKind{reverse}, mode: "reverse:http://example.com", host: "example.com", ignore: []string{"example.com"}, client: []byte(httpGet), want: hookdata.LayerStack{{Kind: tcp, Ignore: true}}},
		"transparent proxy: tls":                                          {before: []hookdata.LayerKind{transparent}, client: plain, want: hookdata.LayerStack{{Kind: serverTLS}, {Kind: clientTLS}}},
		"transparent proxy: raw tcp":                                      {before: []hookdata.LayerKind{transparent}, server: []byte("220 service ready"), want: hookdata.LayerStack{{Kind: tcp}}},
		"transparent proxy: http":                                         {before: []hookdata.LayerKind{transparent}, host: "192.0.2.1", client: []byte(httpGet), want: hookdata.LayerStack{transparentHTTP}},
		"transparent proxy: http via ALPN":                                {before: []hookdata.LayerKind{transparent, serverTLS, clientTLS}, client: []byte("GO /method-too-short-for-heuristic HTTP/1.1\r\n"), alpn: "http/1.1", want: hookdata.LayerStack{transparentHTTP}},
		"transparent proxy: ssh":                                          {before: []hookdata.LayerKind{transparent}, host: "192.0.2.1", client: []byte("SSH-2.0-OpenSSH_9.7"), want: hookdata.LayerStack{{Kind: tcp}}},
		"transparent proxy: tcp_hosts":                                    {before: []hookdata.LayerKind{transparent}, host: "192.0.2.1", client: []byte(httpGet), tcpHosts: []string{"192.0.2.1"}, want: hookdata.LayerStack{{Kind: tcp}}},
		"transparent proxy: ignore_hosts":                                 {before: []hookdata.LayerKind{transparent}, host: "192.0.2.1", client: []byte(httpGet), ignore: []string{"192.0.2.1"}, want: hookdata.LayerStack{{Kind: tcp, Ignore: true}}},
		"transparent proxy: full alpha tcp":                               {before: []hookdata.LayerKind{transparent}, client: []byte("AAAAAAAAAAAAAAAAAAAAAA==\n"), want: hookdata.LayerStack{{Kind: tcp}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, manager, _ := testAddon(t, map[string]any{"ignore_hosts": tt.ignore, "tcp_hosts": tt.tcpHosts})
			c := testContext(a.opts, tt.host, tt.before...)
			if tt.mode != "" {
				c.Client.ProxyMode = tt.mode
			}
			c.Client.ALPN = []byte(tt.alpn)
			d := &hookdata.NextLayer{Context: c, DataClient: tt.client, DataServer: tt.server}
			if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, d.Layer); diff != "" {
				t.Errorf("stack mismatch (-want +got):\n%s", diff)
			}
			var before []hookdata.LayerKind
			for _, l := range c.Layers {
				before = append(before, l.(layerKind).Kind())
			}
			if diff := gocmp.Diff(tt.before, before); diff != "" {
				t.Errorf("parent stack changed (-want +got):\n%s", diff)
			}
		})
	}
}

func TestOptionRows(t *testing.T) {
	tests := map[string]struct{}{
		"ignore_hosts": {}, "allow_hosts": {}, "tcp_hosts": {},
		"udp_hosts": {}, "rawtcp": {}, "show_ignored_hosts": {},
	}
	rows := make(map[string][]string)
	for line := range strings.SplitSeq(strings.TrimSpace(string(testutil.Fixture(t, "options-upstream.txt"))), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("invalid upstream option row: %q", line)
		}
		rows[fields[0]] = fields
	}
	opts := options.New()
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			opt, ok := opts.Lookup(name)
			if !ok {
				t.Fatalf("core option %s is not registered", name)
			}
			def, err := json.Marshal(opt.Default())
			if err != nil {
				t.Fatal(err)
			}
			got := []string{opt.Name(), opt.Type().String(), string(def), opt.Help()}
			if diff := gocmp.Diff(rows[name], got); diff != "" {
				t.Errorf("option row (-upstream +go):\n%s", diff)
			}
		})
	}
}
