// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package contentviews

import (
	"bytes"
	json "encoding/json/v2"
	"fmt"
	rand "math/rand/v2"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// jsCase is one differential input; the data travels to Python as base64.
type jsCase struct {
	Data []byte `json:"data"`
}

// TestJavaScriptDifferential compares the JavaScript view against the
// pinned Python on the upstream fixture and on seeded token soup:
// identical output, with ill-formed UTF-8 replaced the same way on both
// sides.
func TestJavaScriptDifferential(t *testing.T) {
	tests := map[string]jsCase{
		"empty":                     {nil},
		"array":                     {[]byte("[1, 2, 3]")},
		"unclosed array":            {[]byte("[1, 2, 3")},
		"function":                  {[]byte("function(a){[1, 2, 3]}")},
		"lone invalid byte":         {[]byte("\xfe")},
		"truncated sequences":       {[]byte("a\xe6\x97b\xed\xa0\x80c\xf0\x80d\xf4\x90e\xc2")},
		"regex literal":             {[]byte("x=/ab+c/g;y=1")},
		"division":                  {[]byte("x=(a)/b/g;")},
		"regex with escaped slash":  {[]byte(`x=/a\/b/;`)},
		"string with continuation":  {[]byte("x='a\\\nb';y=\"c\\\nd\";")},
		"template literal":          {[]byte("x=`a{;}\nb`;")},
		"line comment":              {[]byte("x=1//c{;}\ny=2")},
		"block comment":             {[]byte("x=1/*{;}\n*/;y=2")},
		"for head":                  {[]byte("for(i=0;i<3;i++){x()}")},
		"empty object then semi":    {[]byte("x={};y={a:1};")},
		"private use page in input": {[]byte("a{}b")},
		"nel and separators":        {[]byte("a{\x85b;\x1cc d\v}e")},
	}
	tests["fixture/simple.js"] = jsCase{testutil.Fixture(t, "mitmproxy/contentviews/javascript/simple.js")}
	tokens := []string{
		"a", "_x", "fn", "{", "}", ";", ":", ",", "(", ")", "=", "/", `\`, `\\`,
		`\/`, "'", `"`, "`", "/*", "*/", "//", "for(", ")", "\n", "\r\n", "\r",
		" ", "\t", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", " ", " ",
		" ", "　", "g", "i", "x", "1", "};", "{}", "\xff", "\xe6\x97",
		"\xf0\x80", "\xc2", "", "", "", "\x00",
	}
	const seed = 904215
	t.Logf("JavaScript differential seed=%d", seed)
	rng := rand.New(rand.NewPCG(seed, 0))
	for i := range 300 {
		var soup bytes.Buffer
		for range 1 + rng.IntN(60) {
			soup.WriteString(tokens[rng.IntN(len(tokens))])
		}
		tests[fmt.Sprintf("generated/%d", i)] = jsCase{soup.Bytes()}
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
from mitmproxy.contentviews._view_javascript import javascript
result = {}
for name, case in json.load(sys.stdin).items():
    data = base64.b64decode(case["data"] or "")
    try:
        result[name] = {"text": javascript.prettify(data, Metadata())}
    except Exception as exc:
        result[name] = {"error": type(exc).__name__}
json.dump(result, sys.stdout)
`, input)
	var reference map[string]struct {
		Text  *string `json:"text"`
		Error string  `json:"error"`
	}
	if err := json.Unmarshal(output, &reference); err != nil {
		t.Fatal(err)
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ref, ok := reference[name]
			if !ok {
				t.Fatal("missing Python result")
			}
			got, err := (JavaScript{}).Prettify(tt.Data, Metadata{})
			if ref.Error != "" {
				if err == nil {
					t.Fatalf("Python raised %s; Go returned %q without error", ref.Error, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Python rendered %q; Go failed: %v", *ref.Text, err)
			}
			if diff := cmp.Diff(*ref.Text, got); diff != "" {
				t.Fatalf("input=%q; Go/Python difference (-Python +Go):\n%s", tt.Data, diff)
			}
		})
	}
}
