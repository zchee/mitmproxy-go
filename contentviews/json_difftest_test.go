// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package contentviews

import (
	json "encoding/json/v2"
	"fmt"
	"math"
	rand "math/rand/v2"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestJSONDifferential(t *testing.T) {
	tests := map[string]struct {
		Data []byte `json:"data"`
	}{
		"duplicate nested objects": {[]byte(`{"b": {"c":0, "a":1, "c":3}, "a":[[],{}], "b":{"x":2}}`)},
		"numbers":                  {[]byte(`[1.0,-0,-0.0,1e16,1e-5,1e400,-1e400,1e-400,123456789012345678901234567890]`)},
		"constants":                {[]byte(`[NaN,Infinity,-Infinity, {"NaN": NaN}]`)},
		"incomplete constant":      {[]byte(`[NaN.1]`)},
		"invalid constant":         {[]byte(`[1Infinity]`)},
		"not a constant":           {[]byte(`"NaN Infinity -Infinity"`)},
		"invalid UTF8":             {[]byte{'"', 0xff, '"'}},
		"literal surrogate":        {[]byte{'"', 0xed, 0xa0, 0x80, '"'}},
		"escaped surrogate":        {[]byte(`"` + `\` + `ud800"`)},
		"surrogate pair":           {[]byte(`"` + `\` + `ud83d` + `\` + `ude00"`)},
		"surrogate duplicate key":  {[]byte(`{"` + `\` + `ud800": 0,"` + string([]byte{0xed, 0xa0, 0x80}) + `":1}`)},
		"UTF16":                    {[]byte{0xff, 0xfe, '[', 0, '1', 0, ']', 0}},
		"UTF32":                    {[]byte{0, 0, 0xfe, 0xff, 0, 0, 0, '[', 0, 0, 0, '1', 0, 0, 0, ']'}},
		"truncated UTF16":          {[]byte{0xff, 0xfe, '[', 0, ']'}},
		"BOM":                      {[]byte("\xef\xbb\xbf{}")},
		"Unicode":                  {[]byte("[\"日本語\",\"  /\"]")},
		"escapes":                  {[]byte(`"\b\f\n\r\t\/\\\""`)},
		"empty":                    {[]byte{}},
		"trailing value":           {[]byte("{}[]")},
		"trailing comma":           {[]byte("[1,]")},
		"integer at limit":         {[]byte(strings.Repeat("1", 4300))},
		"integer over limit":       {[]byte(strings.Repeat("1", 4301))},
	}
	const seed = 837124
	t.Logf("JSON differential seed=%d", seed)
	rng := rand.New(rand.NewPCG(seed, 0))
	for i := range 200 {
		f := math.Float64frombits(rng.Uint64())
		if math.IsNaN(f) || math.IsInf(f, 0) {
			continue
		}
		number := strconv.FormatFloat(f, 'e', -1, 64)
		tests[fmt.Sprintf("generated/%d", i)] = struct {
			Data []byte `json:"data"`
		}{
			fmt.Appendf(nil, `{"first":[%s,{"inner":%s}],"other":%d,"first":[%s]}`, number, number, rng.Uint64(), number),
		}
	}
	input, err := json.Marshal(tests)
	if err != nil {
		t.Fatal(err)
	}
	output := difftest.Python(t, `
import base64
import json
import sys
from mitmproxy.contentviews import Metadata, json_view
result = {}
for name, case in json.load(sys.stdin).items():
    try:
        text = json_view.prettify(base64.b64decode(case["data"]), Metadata())
        result[name] = {"text": base64.b64encode(text.encode("utf-8", "surrogatepass")).decode()}
    except (ValueError, UnicodeError):
        result[name] = {"error": True}
json.dump(result, sys.stdout)
`, input)
	var reference map[string]struct {
		Text  []byte `json:"text,omitzero"`
		Error bool   `json:"error,omitzero"`
	}
	if err := json.Unmarshal(output, &reference); err != nil {
		t.Fatal(err)
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			want, ok := reference[name]
			if !ok {
				t.Fatal("missing Python result")
			}
			got, err := (JSON{}).Prettify(tt.Data, Metadata{})
			if (err != nil) != want.Error {
				t.Fatalf("Go error=%v; Python error=%v; input=%q", err, want.Error, tt.Data)
			}
			if diff := cmp.Diff(string(want.Text), got); diff != "" {
				t.Fatalf("Go/Python difference (-Python +Go):\n%s", diff)
			}
		})
	}
}
