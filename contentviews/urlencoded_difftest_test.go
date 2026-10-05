// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package contentviews

import (
	json "encoding/json/v2"
	"fmt"
	rand "math/rand/v2"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	yaml "go.yaml.in/yaml/v4"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestURLEncodedDifferential(t *testing.T) {
	tests := map[string]struct {
		Data []byte `json:"data"`
	}{
		"empty":            {},
		"invalid escapes":  {[]byte("a=%&a=%2&b=%xy&c=%ff&c=%fe")},
		"byte values":      {[]byte{0, 1, 9, 10, 13, 31, 127, 128, 255, '=', 255}},
		"empty duplicates": {[]byte("a=&a=&b=1&a=2&a=&b=")},
	}
	scalars := []string{"", "true", "True", "TRUE", "false", "yes", "no", "on", "off", "null", "Null", "NULL", "~", "0", "0123", "08", "1_000", "0xFF", "0o12", "0b11", "1:20", "1.0", "1e2", "1E+2", ".nan", ".inf", "-.Inf", "2001-01-01", "2026-99-99", "1.2.3", "word", " a", "a ", "a: b", "a:b", "a # b", "a#b", "- a", "-a", "? a", ": a", "[]", "{}", "*", "&", "!", "|", ">", "'", "\"", "%", "@", "`", "---", "...", "a\nb", "a\tb", "日本語", "a\x00b", "a\u0085b", "a b", "a'b", " ' ", "'\"", "<<", "=", "1e999", strings.Repeat("9", 100), strings.Repeat("word ", 30)}
	for i, scalar := range scalars {
		pair := url.QueryEscape(scalar) + "=" + url.QueryEscape(scalar)
		tests[fmt.Sprintf("scalar/%d", i)] = struct {
			Data []byte `json:"data"`
		}{[]byte(pair)}
	}
	const seed = 771926
	t.Logf("URL-encoded differential seed=%d", seed)
	rng := rand.New(rand.NewPCG(seed, 0))
	for i := range 200 {
		var data strings.Builder
		for range 12 {
			if data.Len() != 0 {
				data.WriteByte('&')
			}
			data.WriteString(url.QueryEscape(scalars[rng.IntN(len(scalars))]))
			data.WriteByte('=')
			data.WriteString(url.QueryEscape(scalars[rng.IntN(len(scalars))]))
		}
		tests[fmt.Sprintf("generated/%d", i)] = struct {
			Data []byte `json:"data"`
		}{[]byte(data.String())}
	}
	input, err := json.Marshal(tests)
	if err != nil {
		t.Fatal(err)
	}
	output := difftest.Python(t, `
import base64
import json
import sys
from mitmproxy.contentviews import Metadata
from mitmproxy.contentviews._view_urlencoded import urlencoded
result = {}
for name, case in json.load(sys.stdin).items():
    result[name] = urlencoded.prettify(base64.b64decode(case["data"] or ""), Metadata())
json.dump(result, sys.stdout)
`, input)
	var reference map[string]string
	if err := json.Unmarshal(output, &reference); err != nil {
		t.Fatal(err)
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			want, ok := reference[name]
			if !ok {
				t.Fatal("missing Python result")
			}
			got, err := (URLEncoded{}).Prettify(tt.Data, Metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(want, got); diff != "" {
				// go-yaml wraps plain values differently from ruamel. Permit
				// only whitespace layout changes with identical decoded values.
				if cmp.Diff(strings.Fields(want), strings.Fields(got)) != "" {
					t.Fatalf("input=%q; Go/Python difference (-Python +Go):\n%s", tt.Data, diff)
				}
				var wantValue, gotValue any
				if err := yaml.Load([]byte(want), &wantValue); err != nil {
					t.Fatal(err)
				}
				if err := yaml.Load([]byte(got), &gotValue); err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(wantValue, gotValue); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}
