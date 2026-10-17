// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package contentviews

import (
	json "encoding/json/v2"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestZIPDifferential(t *testing.T) {
	tests := map[string]struct{ data []byte }{
		"upstream/test_view_zip":                  {zipFixture(t, []string{"normal.txt", "with spaces.txt", "dir/nested.txt", "file\nwith\nnewlines.txt", "unicode_文件.txt", "café.txt"}, false)},
		"upstream/test_view_zip_empty":            {zipFixture(t, nil, false)},
		"filename_encoding/cp437":                 {zipFixture(t, []string{"caf\x82.txt"}, true)},
		"filename_encoding/utf8_flagged":          {zipFixture(t, []string{"café.txt"}, false)},
		"filename_encoding/valid_utf8_flag_clear": {zipFixture(t, []string{"é.txt"}, true)},
	}
	cases := make(map[string][]byte, len(tests))
	for name, tt := range tests {
		cases[name] = tt.data
	}
	input, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	output := difftest.Python(t, `
import base64
import json
import sys
from mitmproxy import http
from mitmproxy.contentviews import Metadata
from mitmproxy.contentviews._view_zip import zip

request = http.Request.make("POST", "https://example.com/", headers={"content-type": "application/zip"})
metadata = Metadata(content_type="application/zip", http_message=request)
result = {"texts": {}, "priorities": []}
for name, encoded in json.load(sys.stdin).items():
    result["texts"][name] = zip.prettify(base64.b64decode(encoded), metadata)
for data, media in [(b"data", "application/zip"), (b"data", "text/plain"), (b"", "application/zip")]:
    result["priorities"].append(zip.render_priority(data, Metadata(content_type=media)))
json.dump(result, sys.stdout)
`, input)
	var reference struct {
		Texts      map[string]string `json:"texts"`
		Priorities []float64         `json:"priorities"`
	}
	if err := json.Unmarshal(output, &reference); err != nil {
		t.Fatal(err)
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			want, found := reference.Texts[name]
			if !found {
				t.Fatal("missing Python ZIP result")
			}
			got, err := (ZIP{}).Prettify(tt.data, Metadata{ContentType: "application/zip"})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	t.Run("upstream/test_render_priority", func(t *testing.T) {
		view := ZIP{}
		got := []float64{view.RenderPriority([]byte("data"), Metadata{ContentType: "application/zip"}), view.RenderPriority([]byte("data"), Metadata{ContentType: "text/plain"}), view.RenderPriority(nil, Metadata{ContentType: "application/zip"})}
		if diff := cmp.Diff(reference.Priorities, got); diff != "" {
			t.Fatal(diff)
		}
	})
}
