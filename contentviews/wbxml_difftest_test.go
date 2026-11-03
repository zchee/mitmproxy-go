// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package contentviews

import (
	json "encoding/json/v2"
	"maps"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestWBXMLDifferential(t *testing.T) {
	fixture, err := os.ReadFile("../testdata/mitmproxy/contentviews/test_wbxml_data/data.wbxml")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{"minimal": {3, 1, 0x6a, 0}, "invalid": []byte("foo"), "fixture": fixture}
	unknown := []byte{3, 1, 0x6a, 0, 0x3f}
	inputs := maps.Clone(cases)
	inputs["unknown"] = unknown
	input, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	output := difftest.Python(t, `
import base64
import json
import sys
from mitmproxy.contentviews import Metadata
from mitmproxy.contentviews._view_wbxml import wbxml

result = {"cases": {}, "priorities": []}
for name, encoded in json.load(sys.stdin).items():
    try:
        result["cases"][name] = {"text": wbxml.prettify(base64.b64decode(encoded), Metadata()), "failed": False}
    except Exception:
        result["cases"][name] = {"text": "", "failed": True}
for media in ["application/vnd.wap.wbxml", "application/vnd.ms-sync.wbxml", "text/plain"]:
    result["priorities"].append(wbxml.render_priority(b"data", Metadata(content_type=media)))
json.dump(result, sys.stdout)
`, input)
	var reference struct {
		Cases map[string]struct {
			Text   string `json:"text"`
			Failed bool   `json:"failed"`
		} `json:"cases"`
		Priorities []float64 `json:"priorities"`
	}
	if err := json.Unmarshal(output, &reference); err != nil {
		t.Fatal(err)
	}
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]func(*testing.T){
			"test_wbxml": func(t *testing.T) {
				for name, data := range cases {
					want, found := reference.Cases[name]
					if !found {
						t.Fatal("missing Python result")
					}
					got, err := (WBXML{}).Prettify(data, Metadata{})
					if (err != nil) != want.Failed {
						t.Fatalf("%s: error=%v want failed=%v", name, err, want.Failed)
					}
					if diff := cmp.Diff(want.Text, got); diff != "" {
						t.Fatalf("%s: %s", name, diff)
					}
				}
			},
			"test_wbxml_unknown_tag": func(t *testing.T) {
				want, found := reference.Cases["unknown"]
				if !found {
					t.Fatal("missing Python unknown-tag result")
				}
				got, err := (WBXML{}).Prettify(unknown, Metadata{})
				if (err != nil) != want.Failed {
					t.Fatalf("unknown tag: error=%v want failed=%v", err, want.Failed)
				}
				if diff := cmp.Diff(want.Text, got); diff != "" {
					t.Fatal(diff)
				}
			},
			"test_render_priority": func(t *testing.T) {
				var got []float64
				for _, media := range []string{"application/vnd.wap.wbxml", "application/vnd.ms-sync.wbxml", "text/plain"} {
					got = append(got, (WBXML{}).RenderPriority([]byte("data"), Metadata{ContentType: media}))
				}
				if diff := cmp.Diff(reference.Priorities, got); diff != "" {
					t.Fatal(diff)
				}
			},
		}
		for name, test := range tests {
			t.Run(name, test)
		}
	})
}
