// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package modespec

import (
	json "encoding/json/v2"
	"fmt"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/netutil/serverspec"
)

type parseInput struct {
	Spec    string
	AsSocks bool
}

type observation struct {
	Error           string
	Name            string
	Common          Spec
	Description     string
	DefaultPort     *int
	Protocol        TransportProtocol
	Host            string
	Port            *int
	HostWithDefault string
	PortWithDefault *int
	Scheme          string
	Address         serverspec.Address
}

const pythonModes = `
import json, sys, unicodedata
from mitmproxy.proxy.mode_specs import ProxyMode, Socks5Mode

inputs = json.load(sys.stdin)
# Cover every digit and whitespace character known to the reference runtime.
for code in range(sys.maxunicode + 1):
    char = chr(code)
    if unicodedata.category(char) == "Nd":
        inputs.append({"Spec": "regular@" + char, "AsSocks": False})
    if char.isspace():
        inputs.append({"Spec": "regular@" + char + "80" + char, "AsSocks": False})
rows = []
for entry in inputs:
    try:
        cls = Socks5Mode if entry["AsSocks"] else ProxyMode
        m = cls.parse(entry["Spec"])
        address = getattr(m, "address", ("", 0))
        result = {
            "Name": m.type_name,
            "Common": {
                "FullSpec": m.full_spec,
                "Data": m.data,
                "CustomListenHost": m.custom_listen_host or "",
                "HasCustomListenHost": m.custom_listen_host is not None,
                "CustomListenPort": m.custom_listen_port or 0,
                "HasCustomListenPort": m.custom_listen_port is not None,
            },
            "Description": m.description,
            "DefaultPort": m.default_port,
            "Protocol": m.transport_protocol,
            "Host": m.listen_host(),
            "Port": m.listen_port(),
            "HostWithDefault": m.listen_host("fallback.example"),
            "PortWithDefault": m.listen_port(4424),
            "Scheme": getattr(m, "scheme", ""),
            "Address": {"Host": address[0], "Port": address[1]},
        }
    except ValueError as e:
        result = {"Error": str(e)}
    rows.append({"Input": entry, "Result": result})
print(json.dumps(rows))
`

func TestDifferentialModes(t *testing.T) {
	bases := []string{
		"", "regular", "regular:", "regular:invalid", "ReGuLaR",
		"transparent", "transparent:data", "socks5", "socKs5", "socks5:data",
		"dns", "dns:data", "wireguard", "wireguard:foo.conf", "wireguard:a@b",
		"WİREGUARD", "local", "local:firefox, ! 123,!!", "local:  ",
		"local:,,", "local: ! ", "local:firefox,", "local:!🦊",
		"tun", "tun:utun42", "tun:utun４٢", "tun:utun3\n", "tun:utun3\n\n", "tun:tun0",
		"osproxy", "osproxy:data", "flibbel", "http3", "@8080",
		"upstream:proxy", "upstream:https://proxy", "upstream:dns://proxy", "upstream:ftp://proxy",
		"upstream", "reverse", "reverse:host", "reverse:https://host/",
		"reverse:dtls://127.0.0.1", "reverse:tcp://host:65536",
		"reverse:tls://[::1]:443", "reverse:https://münich.example",
	}
	for _, scheme := range []string{"http", "https", "http3", "tls", "dtls", "tcp", "udp", "dns", "quic"} {
		bases = append(bases, "reverse:"+scheme+"://example.com:53")
	}
	suffixes := []string{
		"", "@", "@0", "@80", "@65535", "@65536", "@invalid-port", "@-1", "@-0",
		"@+80", "@ 8_0\t", "@_80", "@8__0", "@80_", "@0x50", "@٠８𝟘",
		"@:80", "@host:", "@127.0.0.1:443", "@[::1]:80", "@::1:80",
	}
	var inputs []parseInput
	for _, base := range bases {
		for _, suffix := range suffixes {
			for _, asSocks := range []bool{false, true} {
				inputs = append(inputs, parseInput{Spec: base + suffix, AsSocks: asSocks})
			}
		}
	}
	inputs = append(inputs,
		parseInput{Spec: "regular@" + strings.Repeat("0", 4300)},
		parseInput{Spec: "regular@" + strings.Repeat("0", 4301)},
		parseInput{Spec: "regular@" + strings.Repeat("0_", 4299) + "0"},
	)
	data, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	out := difftest.Python(t, pythonModes, data)
	var rows []struct {
		Input  parseInput
		Result observation
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) < len(inputs) {
		t.Fatalf("reference returned %d rows for %d inputs", len(rows), len(inputs))
	}
	for i, row := range rows {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			var mode Mode
			var err error
			if row.Input.AsSocks {
				mode, err = ParseAs[Socks5Mode](row.Input.Spec)
			} else {
				mode, err = Parse(row.Input.Spec)
			}
			got := observe(mode, err)
			if diff := gocmp.Diff(row.Result, got); diff != "" {
				t.Errorf("spec %q, asSocks=%v (-Python +Go):\n%s", row.Input.Spec, row.Input.AsSocks, diff)
			}
		})
	}
	t.Logf("compared %d mode parses against pinned Python", len(rows))
}

func observe(mode Mode, err error) observation {
	if err != nil {
		return observation{Error: err.Error()}
	}
	got := observation{
		Name: mode.Name(), Common: mode.Common(), Description: mode.Description(),
		Protocol: mode.TransportProtocol(), Host: mode.ListenHost(""),
		HostWithDefault: mode.ListenHost("fallback.example"),
	}
	if port, ok := mode.DefaultPort(); ok {
		got.DefaultPort = new(port)
	}
	if port, ok := mode.ListenPort(nil); ok {
		got.Port = new(port)
	}
	if port, ok := mode.ListenPort(new(4424)); ok {
		got.PortWithDefault = new(port)
	}
	switch m := mode.(type) {
	case ReverseMode:
		got.Scheme, got.Address = m.Scheme, m.Address
	case UpstreamMode:
		got.Scheme, got.Address = m.Scheme, m.Address
	}
	return got
}
