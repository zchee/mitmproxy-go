// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package proxyauth

import (
	"encoding/base64"
	json "encoding/json/v2"
	"fmt"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestDifferentialBasicAuth(t *testing.T) {
	tests := map[string]struct{ header string }{
		"lowercase": {"basic dGVzdDp0ZXN0"},
		"long s":    {"baſic dGVzdDp0ZXN0"},
		"uppercase": {"BASIC dGVzdDp0ZXN0"},
	}
	for _, space := range []rune{' ', '\t', '\n', '\r', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x1f', '\u0085', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '　'} {
		tests[fmt.Sprintf("whitespace %x", space)] = struct{ header string }{"basic" + string(space) + "dGVzdDp0ZXN0"}
	}
	for _, encoded := range []string{"Og==", "dTo=", "dTpw", "dXNlcjpwYXNz", "YQ==", "", "/zo=", "4oI6", "7aCAOg==", "8J+SOg=="} {
		for i := 0; i <= len(encoded); i++ {
			for _, insert := range []string{"", "=", "==", "===", "!", "é", "\x00", "A"} {
				header := "basic " + encoded[:i] + insert + encoded[i:]
				tests[header] = struct{ header string }{header}
			}
		}
	}
	for value := range 256 {
		header := "basic " + base64.StdEncoding.EncodeToString([]byte{byte(value), ':', byte(value)})
		tests[header] = struct{ header string }{header}
	}
	headers := make(map[string]string, len(tests))
	for name, tt := range tests {
		headers[name] = tt.header
	}
	data, err := json.Marshal(headers)
	if err != nil {
		t.Fatal(err)
	}
	out := difftest.Python(t, `
import json, sys
from mitmproxy.addons.proxyauth import parse_http_basic_auth
results = {}
for name, header in json.load(sys.stdin).items():
    try:
        results[name] = parse_http_basic_auth(header)
    except ValueError:
        results[name] = None
print(json.dumps(results))
`, data)
	var results map[string][]string
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != len(tests) {
		t.Fatalf("oracle returned %d results for %d inputs", len(results), len(tests))
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			scheme, user, password, err := ParseHTTPBasicAuth(tt.header)
			var got []string
			if err == nil {
				got = []string{scheme, user, password}
			}
			if diff := gocmp.Diff(results[name], got); diff != "" {
				t.Fatalf("header %q (-Python +Go):\n%s", tt.header, diff)
			}
		})
	}
	t.Logf("compared %d headers against pinned Python", len(tests))
}
