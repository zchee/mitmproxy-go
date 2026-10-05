// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package contentviews

import (
	json "encoding/json/v2"
	"fmt"
	rand "math/rand/v2"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestXMLHTMLDifferential(t *testing.T) {
	tests := map[string]struct {
		Data []byte `json:"data"`
	}{
		"incomplete comment":      {[]byte("<a><!-- one > two")},
		"incomplete CDATA":        {[]byte("<a><![CDATA[ one > two")},
		"lookahead tag name":      {[]byte("<foo=bar>x</fo><x=bar>y</bar>")},
		"newline indentation":     {[]byte("<a>\r\n\t foo\n\t bar\n</a>")},
		"Unicode line boundaries": {[]byte("<a><b>a\v b\f c\r d\x1c e\x1d f\x1e g\u0085 h  i  j</b></a>")},
		"Unicode whitespace":      {[]byte("\x1f<a>\x1f text\x1f </a>\x1f")},
		"no-indent closing":       {[]byte("<a><html></html><p>text</p></a>")},
		"bounded stack":           {[]byte(strings.Repeat("<div>", 30) + "x" + strings.Repeat("</div>", 30))},
		"invalid UTF8":            {[]byte{'<', 'a', '>', 0xff, '<', '/', 'a', '>'}},
	}
	const seed = 63729
	t.Logf("XML differential seed=%d", seed)
	rng := rand.New(rand.NewPCG(seed, 0))
	fragments := []string{"<a>", "</a>", "<b/>", "<html>", "</html>", "<!-- a > b -->", "<![CDATA[a > b]]>", "<>", "</>", "<img>", "<A x=\"2\">", "text", " \n ", "\ttext\n text\n", "<", ">", "<a=b>", "日本語"}
	for i := range 200 {
		var text strings.Builder
		for range 25 {
			text.WriteString(fragments[rng.IntN(len(fragments))])
		}
		tests[fmt.Sprintf("generated/%d", i)] = struct {
			Data []byte `json:"data"`
		}{[]byte(text.String())}
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
from mitmproxy.contentviews._view_xml_html import xml_html
result = {}
for name, case in json.load(sys.stdin).items():
    text = xml_html.prettify(base64.b64decode(case["data"]), Metadata())
    result[name] = text
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
			got, err := (XMLHTML{}).Prettify(tt.Data, Metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Fatalf("input=%q; Go/Python difference (-Python +Go):\n%s", tt.Data, diff)
			}
		})
	}
}
