// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestJSON ports test__view_json.py and adds Python JSON boundary cases.
func TestJSON(t *testing.T) {
	tests := map[string]struct {
		data string
		want string
		err  bool
	}{
		"test_view_json null":               {"null", "null", false},
		"test_view_json object":             {"{}", "{}", false},
		"test_view_json truncated":          {"{", "", true},
		"test_view_json array":              {"[1, 2, 3, 4, 5]", "[\n    1,\n    2,\n    3,\n    4,\n    5\n]", false},
		"test_view_json member":             {`{"foo" : 3}`, "{\n    \"foo\": 3\n}", false},
		"test_view_json literals":           {`{"foo": true, "nullvalue": null}`, "{\n    \"foo\": true,\n    \"nullvalue\": null\n}", false},
		"test_view_json empty array":        {"[]", "[]", false},
		"test_view_json_nonascii":           {`{"a": "日本語"}`, "{\n    \"a\": \"日本語\"\n}", false},
		"duplicate keeps original position": {`{"b": 1, "a": 2, "b": 3}`, "{\n    \"b\": 3,\n    \"a\": 2\n}", false},
		"Python float and integer":          {"[1e0,-0,-0.0,1e16,1e-5,1e400,-1e400,1e-400,123456789012345678901234567890]", "[\n    1.0,\n    0,\n    -0.0,\n    1e+16,\n    1e-05,\n    Infinity,\n    -Infinity,\n    0.0,\n    123456789012345678901234567890\n]", false},
		"nonfinite":                         {"[NaN,Infinity,-Infinity]", "[\n    NaN,\n    Infinity,\n    -Infinity\n]", false},
		"nonfinite inside string":           {`"NaN Infinity -Infinity"`, `"NaN Infinity -Infinity"`, false},
		"lone high surrogate":               {`"` + `\` + `ud800"`, "\"\xed\xa0\x80\"", false},
		"lone low surrogate":                {`"` + `\` + `udfff"`, "\"\xed\xbf\xbf\"", false},
		"paired surrogates":                 {`"` + `\` + `ud83d` + `\` + `ude00"`, `"😀"`, false},
		"literal surrogate":                 {"\"\xed\xa0\x80\"", "\"\xed\xa0\x80\"", false},
		"invalid UTF8":                      {"\"\xff\"", "", true},
		"UTF8 BOM":                          {"\xef\xbb\xbf{}", "{}", false},
		"UTF16 BOM":                         {"\xff\xfe[\x001\x00]\x00", "[\n    1\n]", false},
		"UTF16 big endian":                  {"\x00[\x001\x00]", "[\n    1\n]", false},
		"UTF32 little endian":               {"[\x00\x00\x001\x00\x00\x00]\x00\x00\x00", "[\n    1\n]", false},
		"UTF32 big endian":                  {"\x00\x00\x00[\x00\x00\x001\x00\x00\x00]", "[\n    1\n]", false},
		"truncated UTF16":                   {"\xff\xfe[", "", true},
		"invalid UTF32":                     {"\xff\xfe\x00\x00\x00\x00\x11\x00", "", true},
		"line separators":                   {"\"  /\"", "\"  /\"", false},
		"escapes":                           {`"\b\f\n\r\t\/\\\""`, `"\b\f\n\r\t/\\\""`, false},
		"empty":                             {"", "", true},
		"trailing value":                    {"{}[]", "", true},
		"trailing comma":                    {"[1,]", "", true},
		"literal control":                   {"\"\n\"", "", true},
		"bad escape":                        {`"\x20"`, "", true},
		"bad constant suffix":               {"NaN.1", "", true},
		"bad signed constant":               {"-NaN", "", true},
		"bad numeric constant":              {"1Infinity", "", true},
		"nonfinite member name":             {"{NaN: 1}", "", true},
		"depth bound":                       {strings.Repeat("[", 1025) + strings.Repeat("]", 1025), "", true},
		"integer conversion bound":          {strings.Repeat("1", 4301), "", true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := (JSON{}).Prettify([]byte(tt.data), Metadata{})
			if (err != nil) != tt.err {
				t.Fatalf("Prettify error = %v; want error %v", err, tt.err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	if got := (JSON{}).SyntaxHighlight(); got != "yaml" {
		t.Fatalf("syntax = %q; want yaml", got)
	}
}

func TestJSONRenderPriority(t *testing.T) {
	tests := map[string]struct {
		data        string
		contentType string
		want        float64
	}{
		"application/json":         {"data", "application/json", 1},
		"application/json-rpc":     {"data", "application/json-rpc", 1},
		"application/vnd.api+json": {"data", "application/vnd.api+json", 1},
		"application/acme+json":    {"data", "application/acme+json", 1},
		"text/plain":               {"data", "text/plain", 0},
		"empty":                    {"", "application/json", 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := (JSON{}).RenderPriority([]byte(tt.data), Metadata{ContentType: tt.contentType})
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
