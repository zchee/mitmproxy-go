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

// cssCase is one differential input; the data travels to Python as base64.
type cssCase struct {
	Data []byte `json:"data"`
}

// TestCSSDifferential compares the CSS view against the pinned Python on
// the upstream fixtures and on seeded token soup: byte-identical output,
// with undecodable bytes read back through surrogateescape on the Python
// side.
func TestCSSDifferential(t *testing.T) {
	tests := map[string]cssCase{
		"empty":                        {nil},
		"simple rule":                  {[]byte("#foo{color:red}")},
		"not css":                      {[]byte("console.log('not really css')")},
		"unterminated string":          {[]byte("a{content:'unterminated}")},
		"unterminated comment":         {[]byte("a{/*no end")},
		"escaped quote":                {[]byte(`a{content:'\';b:c'}`)},
		"double escapes before quote":  {[]byte(`a{content:'x\\\\';d:e}`)},
		"line comment at end":          {[]byte("a{b:c}//trailing")},
		"private use page in input":    {[]byte("a{content:''}")},
		"undecodable bytes":            {[]byte("a{b:'\xff\xfe\x80'}")},
		"nel and nbsp whitespace":      {[]byte("a\u0085{ b:c; d:e　}")},
		"separator control whitespace": {[]byte("a\x1c{\x1db:c;\x1ed\x1f:e}")},
		"carriage returns":             {[]byte("a{//c\r\nb:c;\rd:e}")},
	}
	fixtures := []string{
		"animation-keyframe",
		"blank-lines-and-spaces",
		"block-comment",
		"empty-rule",
		"import-directive",
		"indentation",
		"media-directive",
		"quoted-string",
		"selectors",
		"simple",
	}
	for _, fixture := range fixtures {
		tests["fixture/"+fixture] = cssCase{testutil.Fixture(t, "mitmproxy/contentviews/css/"+fixture+".css")}
	}
	tokens := []string{
		"a", "#foo", ".cls", "@media", "{", "}", ";", ":", ",", " ", "  ", "\t",
		"\n", "\r\n", "\r", "'", `"`, `\`, `\\`, "/*", "*/", "//", "$", "red",
		"url('x')", "\u0085", " ", " ", " ", " ", " ",
		" ", " ", " ", "　", "\x1c", "\x1d", "\x1e", "\x1f",
		"\x0b", "\x0c", "\xff", "\xc2", "\xe6\x97", "", "", "\x00",
	}
	const seed = 731248
	t.Logf("CSS differential seed=%d", seed)
	rng := rand.New(rand.NewPCG(seed, 0))
	for i := range 300 {
		var soup bytes.Buffer
		for range 1 + rng.IntN(60) {
			soup.WriteString(tokens[rng.IntN(len(tokens))])
		}
		tests[fmt.Sprintf("generated/%d", i)] = cssCase{soup.Bytes()}
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
from mitmproxy.contentviews._view_css import css
result = {}
for name, case in json.load(sys.stdin).items():
    data = base64.b64decode(case["data"] or "")
    try:
        text = css.prettify(data, Metadata())
        encoded = base64.b64encode(text.encode("utf8", "surrogateescape"))
        result[name] = {"text": encoded.decode("ascii")}
    except Exception as exc:
        result[name] = {"error": type(exc).__name__}
json.dump(result, sys.stdout)
`, input)
	var reference map[string]struct {
		Text  []byte `json:"text"`
		Error string `json:"error"`
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
			got, err := (CSS{}).Prettify(tt.Data, Metadata{})
			if ref.Error != "" {
				if err == nil {
					t.Fatalf("Python raised %s; Go returned %q without error", ref.Error, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Python rendered %q; Go failed: %v", ref.Text, err)
			}
			if diff := cmp.Diff(string(ref.Text), got); diff != "" {
				t.Fatalf("input=%q; Go/Python difference (-Python +Go):\n%s", tt.Data, diff)
			}
		})
	}
}
