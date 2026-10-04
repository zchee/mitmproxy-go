// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package options

import (
	json "encoding/json/v2"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// coreOptionNames lists the options of upstream's Options class
// (mitmproxy/options.py) in registration order. Their types, defaults and
// help texts come from testdata/options-upstream.txt.
var coreOptionNames = []string{
	"server",
	"showhost",
	"show_ignored_hosts",
	"add_upstream_certs_to_client_chain",
	"confdir",
	"certs",
	"cert_passphrase",
	"client_certs",
	"ignore_hosts",
	"allow_hosts",
	"listen_host",
	"listen_port",
	"mode",
	"upstream_cert",
	"http2",
	"http2_ping_keepalive",
	"http3",
	"http_connect_send_host_header",
	"websocket",
	"rawtcp",
	"ssl_insecure",
	"ssl_verify_upstream_trusted_confdir",
	"ssl_verify_upstream_trusted_ca",
	"tcp_hosts",
	"udp_hosts",
	"content_view_lines_cutoff",
	"key_size",
	"protobuf_definitions",
	"tcp_timeout",
}

// optionRow is one line of testdata/options-upstream.txt: name, type as
// upstream's typespec_to_str renders it, default (decoded from JSON) and the
// normalised help text.
type optionRow struct {
	Name    string
	Type    string
	Default any
	Help    string
}

func upstreamOptions(t *testing.T) map[string]optionRow {
	t.Helper()
	const rel = "options-upstream.txt"
	rows := make(map[string]optionRow)
	for n, line := range strings.Split(strings.TrimSuffix(string(testutil.Fixture(t, rel)), "\n"), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("%s:%d: %d tab-separated fields, want 4", rel, n+1, len(fields))
		}
		var def any
		if err := json.Unmarshal([]byte(fields[2]), &def); err != nil {
			t.Fatalf("%s:%d: default %s: %v", rel, n+1, fields[2], err)
		}
		rows[fields[0]] = optionRow{Name: fields[0], Type: fields[1], Default: def, Help: fields[3]}
	}
	return rows
}

// jsonValue converts an option value to the shape a JSON decoder produces
// for the same value, so it can be compared with the upstream default.
func jsonValue(v any) any {
	switch x := v.(type) {
	case int:
		return float64(x)
	case *int:
		if x == nil {
			return nil
		}
		return float64(*x)
	case *string:
		if x == nil {
			return nil
		}
		return *x
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	}
	return v
}

// TestCoreOptions checks that New registers exactly upstream's 29 core
// options, in upstream's order, with upstream's types, defaults and help
// texts.
func TestCoreOptions(t *testing.T) {
	upstream := upstreamOptions(t)
	if len(coreOptionNames) != 29 {
		t.Fatalf("coreOptionNames lists %d options, want 29", len(coreOptionNames))
	}
	want := make([]optionRow, len(coreOptionNames))
	for i, name := range coreOptionNames {
		row, ok := upstream[name]
		if !ok {
			t.Fatalf("core option %s is missing from testdata/options-upstream.txt", name)
		}
		want[i] = row
	}

	items := New().Items()
	got := make([]optionRow, len(items))
	for i, o := range items {
		got[i] = optionRow{Name: o.Name(), Type: o.Type().String(), Default: jsonValue(o.Default()), Help: o.Help()}
		if o.Choices() != nil {
			t.Errorf("core option %s has choices %v; upstream's core options have none", o.Name(), o.Choices())
		}
	}
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Errorf("core options mismatch (-upstream +go):\n%s", diff)
	}
}

func TestCoreOptionValues(t *testing.T) {
	m := New()
	tests := map[string]struct {
		get  func() any
		want any
	}{
		"success: server":                    {get: func() any { return m.Bool("server") }, want: true},
		"success: confdir":                   {get: func() any { return m.Str("confdir") }, want: ConfDir},
		"success: listen_host":               {get: func() any { return m.Str("listen_host") }, want: ""},
		"success: listen_port":               {get: func() any { return m.OptInt("listen_port") }, want: (*int)(nil)},
		"success: mode":                      {get: func() any { return m.Seq("mode") }, want: []string{"regular"}},
		"success: certs":                     {get: func() any { return m.Seq("certs") }, want: []string{}},
		"success: cert_passphrase":           {get: func() any { return m.OptStr("cert_passphrase") }, want: (*string)(nil)},
		"success: http2_ping_keepalive":      {get: func() any { return m.Int("http2_ping_keepalive") }, want: 58},
		"success: content_view_lines_cutoff": {get: func() any { return m.Int("content_view_lines_cutoff") }, want: ContentViewLinesCutoff},
		"success: key_size":                  {get: func() any { return m.Int("key_size") }, want: KeySize},
		"success: tcp_timeout":               {get: func() any { return m.Int("tcp_timeout") }, want: 600},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, tt.get()); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
