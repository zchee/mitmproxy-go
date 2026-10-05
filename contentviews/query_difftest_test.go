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

	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestQueryDifferential(t *testing.T) {
	tests := map[string]struct {
		Path string `json:"path"`
	}{
		"empty":                            {"/"},
		"invalid escapes":                  {"/?a=%&a=%2&b=%xy&c=%ff&c=%fe"},
		"invalid UTF-8":                    {"/?a=%ed%a0%80&b=%f0%9f&c=%c0%80&d=%e2%82x"},
		"empty duplicates":                 {"/?a=&a=&b=1&a=2&a=&b="},
		"fragment":                         {"/path;params?a=b#c=d"},
		"invalid key with line breaks":     {"/?a%FF%0Ab=x&a%FF%C2%85b=y"},
		"invalid scalar token collisions":  {"/?%00=%00%000&%FF=%00%001&k=%5C%220&v=%FF%00%5C0"},
		"invalid scalar nonce collisions":  {"/?a=%000%001%002%00&b=%00%00%003%00&k=%FF"},
		"invalid scalar printable Unicode": {"/?k=%FF%C2%A0%E6%97%A5%E6%9C%AC"},
		"long invalid key":                 {"/?" + strings.Repeat("%FF", 128) + "=x"},
		"long invalid value":               {"/?key=" + strings.Repeat("%FF", 128)},
		"long invalid value with spaces":   {"/?key=" + strings.Repeat("%FF+word+", 32)},
		"long invalid sequence":            {"/?k=x&k=" + strings.Repeat("%FF", 128)},
		"invalid key near limit":           {"/?" + strings.Repeat("a", 120) + "%FF=x"},
		"invalid scalar quotes":            {"/?k=%FF%27%22%5C%00%01%07%08%09%0A%0B%0C%0D%1B%7F%C2%85%C2%A0%E2%80%A8%E2%80%A9%EF%BB%BF%EF%BF%BE%EF%BF%BF"},
	}
	scalars := []string{"", "true", "false", "yes", "null", "~", "0", "08", "1e999", "0o12", "2026-99-99", " a", "a ", "a: b", "a # b", "- a", "? a", "[]", "{}", "*", "&", "!", "|", ">", "'", "\"", "%", "@", "`", "---", "...", "a\nb", "a\tb", "日本語", "a\x00b", "a\x85b", "a\u0085b", "a b", "a b", "a\U0000FEFFb", "a'b", " ' ", "<<", "=", "🙂", strings.Repeat("word ", 30)}
	for i, scalar := range scalars {
		tests[fmt.Sprintf("scalar/%d", i)] = struct {
			Path string `json:"path"`
		}{"/?" + url.QueryEscape(scalar) + "=" + url.QueryEscape(scalar)}
	}
	const seed = 918265
	t.Logf("Query differential seed=%d", seed)
	rng := rand.New(rand.NewPCG(seed, 0))
	for i := range 200 {
		var path strings.Builder
		path.WriteString("/?")
		for j := range 12 {
			if j != 0 {
				path.WriteByte('&')
			}
			path.WriteString(url.QueryEscape(scalars[rng.IntN(len(scalars))]))
			path.WriteByte('=')
			path.WriteString(url.QueryEscape(scalars[rng.IntN(len(scalars))]))
		}
		tests[fmt.Sprintf("generated/%d", i)] = struct {
			Path string `json:"path"`
		}{path.String()}
	}
	cases := make(map[string]map[string]string, len(tests))
	for name, tt := range tests {
		request := testflow.TReq()
		request.Path = tt.Path
		text, err := (Query{}).Prettify(nil, Metadata{HTTPRequest: request})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		cases[name] = map[string]string{"path": tt.Path, "text": text}
	}
	input, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	output := difftest.Python(t, `
import json
import re
import sys
from ruamel.yaml import YAML
from ruamel.yaml.tokens import ScalarToken
from mitmproxy.contentviews import Metadata
from mitmproxy.contentviews._utils import merge_repeated_keys, yaml_loads
from mitmproxy.contentviews._view_query import query
from mitmproxy.test import tutils

def mask_scalars(text, expected):
    tokens = [token for token in YAML(typ="safe", pure=True).scan(text)
              if isinstance(token, ScalarToken)]
    assert len(tokens) == len(expected), (text, expected)
    for token, original in reversed(list(zip(tokens, expected))):
        if chr(0x85) in original or any(ord(char) > 0xffff for char in original):
            text = text[:token.start_mark.index] + "<unicode-scalar>" + text[token.end_mark.index:]
        elif any(0xdc80 <= ord(char) <= 0xdcff for char in original):
            assert token.style == '"', (original, token)
            scalar = text[token.start_mark.index:token.end_mark.index]
            scalar = re.sub(r"\\\n[ \t]*(?:\\(?= ))?", "", scalar)
            text = text[:token.start_mark.index] + scalar + text[token.end_mark.index:]
    return text

result = {}
for name, case in json.load(sys.stdin).items():
    request = tutils.treq()
    request.path = case["path"]
    expected = merge_repeated_keys(request.query.items(multi=True))
    reference = query.prettify(b"", Metadata(http_message=request))
    # Check the original strings, not ruamel's NEL-losing roundtrip.
    decoded = yaml_loads(case["text"])
    assert decoded == (expected or None), (name, decoded, expected)
    assert not expected or list(decoded) == list(expected), name
    scalars = []
    for key, value in expected.items():
        scalars.append(key)
        scalars.extend(value if isinstance(value, list) else [value])
    result[name] = {
        "want": mask_scalars(reference, scalars),
        "got": mask_scalars(case["text"], scalars),
    }
json.dump(result, sys.stdout)
`, input)
	var reference map[string]struct {
		Want string `json:"want"`
		Got  string `json:"got"`
	}
	if err := json.Unmarshal(output, &reference); err != nil {
		t.Fatal(err)
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result, ok := reference[name]
			if !ok {
				t.Fatal("missing Python result")
			}
			if diff := cmp.Diff(result.Want, result.Got); diff != "" {
				// Beyond the masked Unicode scalars, only documented plain-word
				// wrapping may differ. The Python check above proves string values.
				if cmp.Diff(strings.Fields(result.Want), strings.Fields(result.Got)) != "" {
					t.Fatalf("path=%q; Go/Python difference (-Python +Go):\n%s", tt.Path, diff)
				}
			}
		})
	}
}
