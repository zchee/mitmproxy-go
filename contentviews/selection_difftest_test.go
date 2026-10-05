// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package contentviews

import (
	json "encoding/json/v2"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// selectionCase is one differential input: a body with its content type.
// Every case's winning view is one the port has built, so the Python
// registry with its full view set and the Go registry must agree.
type selectionCase struct {
	Data        []byte `json:"data"`
	ContentType string `json:"content_type"`
}

// TestSelectionDifferential compares automatic view selection and the
// selected view's rendered text against the pinned Python.
func TestSelectionDifferential(t *testing.T) {
	tests := map[string]selectionCase{
		"plain text":             {Data: []byte("foo")},
		"empty body":             {Data: []byte{}},
		"binary":                 {Data: []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")},
		"html":                   {Data: []byte("<html></html>"), ContentType: "text/html"},
		"xml sniffed":            {Data: []byte("<xml></xml>"), ContentType: "text/flibble"},
		"svg":                    {Data: []byte("<svg></svg>"), ContentType: "image/svg+xml"},
		"structured json suffix": {Data: []byte(`{"a": [1, null, "x"]}`), ContentType: "application/acme+json"},
		"json":                   {Data: []byte(`{"b": 1.5, "a": true}`), ContentType: "application/json"},
		"css":                    {Data: []byte("#foo{color:red;background:blue}"), ContentType: "text/css"},
		"javascript":             {Data: []byte("function(a){[1, 2, 3]}"), ContentType: "application/javascript"},
		"x-javascript":           {Data: []byte("x=1;y=2"), ContentType: "application/x-javascript"},
		"urlencoded":             {Data: []byte("one=two&three=four&three=five"), ContentType: "application/x-www-form-urlencoded"},
		"unknown content type":   {Data: []byte("foo"), ContentType: "text/flibble"},
		"unknown image format":   {Data: []byte("verybinary"), ContentType: "image/new-magic-image-format"},
		"non-css under text/css": {Data: []byte("console.log('x')"), ContentType: "text/css"},
		"binary under text/html": {Data: []byte("<html>\xff\xfe</html>"), ContentType: "text/html"},
		"multipart":              {Data: []byte("--b\r\nContent-Disposition: form-data; name=\"k\"\r\n\r\nv\r\n--b--\r\n"), ContentType: "multipart/form-data; boundary=b"},
	}
	tests["png"] = selectionCase{Data: testutil.Fixture(t, "mitmproxy/image.png"), ContentType: "image/png"}
	tests["gif"] = selectionCase{Data: testutil.Fixture(t, "mitmproxy/image.gif"), ContentType: "image/gif"}
	input, err := json.Marshal(tests)
	if err != nil {
		t.Fatal(err)
	}
	output := difftest.Python(t, `
import base64
import json
import sys
from mitmproxy.contentviews import Metadata
from mitmproxy.contentviews import registry
result = {}
for name, case in json.load(sys.stdin).items():
    data = base64.b64decode(case["data"] or "")
    metadata = Metadata(content_type=case["content_type"].split(";")[0] or None)
    view = registry.get_view(data, metadata)
    entry = {"view": view.name}
    try:
        text = view.prettify(data, metadata)
        entry["text"] = base64.b64encode(
            text.encode("utf-8", "surrogateescape")
        ).decode("ascii")
    except Exception as exc:
        entry["error"] = type(exc).__name__
    result[name] = entry
json.dump(result, sys.stdout)
`, input)
	var reference map[string]struct {
		View  string `json:"view"`
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
			contentType, _, _ := strings.Cut(tt.ContentType, ";")
			metadata := Metadata{ContentType: contentType}
			view, err := NewRegistry().GetView(tt.Data, metadata, "auto")
			if err != nil {
				t.Fatalf("GetView() error = %v", err)
			}
			if view.Name() != ref.View {
				t.Fatalf("GetView() selected %q, Python selected %q", view.Name(), ref.View)
			}
			if ref.View == "Image" {
				// Rendered-text parity for image metadata, including the
				// known YAML wrapping differences, is TestImageDifferential's
				// job; here the selection is the subject.
				return
			}
			got, err := view.Prettify(tt.Data, metadata)
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
				t.Fatalf("Go/Python difference (-Python +Go):\n%s", diff)
			}
		})
	}
}
