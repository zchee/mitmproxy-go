// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package contentviews

import (
	"bytes"
	json "encoding/json/v2"
	"fmt"
	rand "math/rand/v2"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	yaml "go.yaml.in/yaml/v4"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

// multipartPart builds one form part the way upstream's encoder lays it out.
func multipartPart(boundary string, name, value []byte) []byte {
	var part bytes.Buffer
	part.WriteString("--")
	part.WriteString(boundary)
	part.WriteString("\r\nContent-Disposition: form-data; name=\"")
	part.Write(name)
	part.WriteString("\"\r\n\r\n")
	part.Write(value)
	part.WriteString("\r\n")
	return part.Bytes()
}

func TestMultipartDifferential(t *testing.T) {
	const boundary = "AaB03x"
	contentType := "multipart/form-data; boundary=" + boundary
	tests := map[string]struct {
		ContentType *string `json:"content_type"`
		Data        []byte  `json:"data"`
	}{
		"upstream body":            {&contentType, []byte(multipartBody)},
		"no boundary":              {ptr("multipart/form-data"), []byte(multipartBody)},
		"unparseable content type": {ptr("unparseable"), []byte(multipartBody)},
		"empty body":               {&contentType, nil},
		"missing header":           {nil, []byte(multipartBody)},
		"part without blank line":  {&contentType, []byte("--" + boundary + "\r\nContent-Disposition: form-data; name=\"k\"\r\nLarry\r\n--" + boundary + "--")},
		"boundary inside value":    {&contentType, append(multipartPart(boundary, []byte("k"), []byte("a--"+boundary+"b")), []byte("--"+boundary+"--")...)},
		"non-ASCII boundary":       {ptr("multipart/form-data; boundary=é"), []byte(multipartBody)},
	}
	names := [][]byte{[]byte("k"), []byte("key name"), []byte("a=b"), []byte("a: b"), []byte("---"), []byte("null"), []byte("0123"), []byte("a'b"), []byte("a\\b"), {0xff, 0xfe}, []byte("\xe6\x97\xa5"), []byte("k\x00v"), []byte(strings.Repeat("n", 90))}
	values := [][]byte{nil, []byte("true"), []byte("1e999"), []byte("2026-99-99"), []byte("a: b"), []byte("- a"), []byte("'"), []byte("\""), []byte("%"), []byte("a\nb"), []byte("a\r\nb"), []byte("a\tb"), []byte("\xe6\x97\xa5\xe6\x9c\xac"), {0, 1, 9, 31, 127, 128, 255}, []byte("a\x85b"), []byte("a\xc2\x85b"), []byte(" a "), []byte(strings.Repeat("word ", 30)), []byte(strings.Repeat("\xff", 80))}
	const seed = 442871
	t.Logf("Multipart differential seed=%d", seed)
	rng := rand.New(rand.NewPCG(seed, 0))
	for i := range 150 {
		var body bytes.Buffer
		for range 1 + rng.IntN(8) {
			body.Write(multipartPart(boundary, names[rng.IntN(len(names))], values[rng.IntN(len(values))]))
		}
		body.WriteString("--" + boundary + "--")
		tests[fmt.Sprintf("generated/%d", i)] = struct {
			ContentType *string `json:"content_type"`
			Data        []byte  `json:"data"`
		}{&contentType, body.Bytes()}
	}
	input, err := json.Marshal(tests)
	if err != nil {
		t.Fatal(err)
	}
	output := difftest.Python(t, `
import base64
import json
import sys
from mitmproxy import http
from mitmproxy.contentviews import Metadata
from mitmproxy.contentviews._view_multipart import multipart
result = {}
for name, case in json.load(sys.stdin).items():
    headers = {}
    if case["content_type"] is not None:
        headers["content-type"] = case["content_type"]
    request = http.Request.make("POST", "https://example.com/", headers=headers)
    data = base64.b64decode(case["data"] or "")
    try:
        result[name] = {"text": multipart.prettify(data, Metadata(http_message=request))}
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
			metadata := Metadata{}
			request := testflow.TReq()
			request.Headers = httpmsg.Headers{}
			if tt.ContentType != nil {
				request.Headers.Set("content-type", *tt.ContentType)
			}
			metadata.HTTPMessage = &request.Message
			got, err := (Multipart{}).Prettify(tt.Data, metadata)
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
				// go-yaml wraps plain values differently from ruamel. Permit
				// only whitespace layout changes with identical decoded values.
				if cmp.Diff(strings.Fields(*ref.Text), strings.Fields(got)) != "" {
					t.Fatalf("input=%q; Go/Python difference (-Python +Go):\n%s", tt.Data, diff)
				}
				var wantValue, gotValue any
				if err := yaml.Load([]byte(*ref.Text), &wantValue); err != nil {
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

// ptr returns a pointer to its argument for literal test tables.
func ptr[T any](v T) *T { return &v }
