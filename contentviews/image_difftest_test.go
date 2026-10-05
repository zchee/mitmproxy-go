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
	yaml "go.yaml.in/yaml/v4"

	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// imageCase is one differential input; the data travels to Python as base64.
type imageCase struct {
	Data []byte `json:"data"`
}

// TestImageDifferential compares the image view against the pinned Python
// on the upstream fixtures, on truncated prefixes, on seeded single-byte
// mutations and on crafted malformed inputs: identical text, or an
// exception on both sides.
func TestImageDifferential(t *testing.T) {
	fixtures := []string{
		"mitmproxy/image_parser/all.jpeg",
		"mitmproxy/image_parser/app1.jpeg",
		"mitmproxy/image_parser/aspect.png",
		"mitmproxy/image_parser/chi.gif",
		"mitmproxy/image_parser/comment.jpg",
		"mitmproxy/image_parser/ct0n0g04.png",
		"mitmproxy/image_parser/ct1n0g04.png",
		"mitmproxy/image_parser/cten0g04.png",
		"mitmproxy/image_parser/ctzn0g04.png",
		"mitmproxy/image_parser/example.jpg",
		"mitmproxy/image_parser/g07n0g16.png",
		"mitmproxy/image_parser/hopper.gif",
		"mitmproxy/image_parser/iss634.gif",
		"mitmproxy/image.png",
		"mitmproxy/image.gif",
		"mitmproxy/image.ico",
		"mitmproxy/image.jpg",
		"mitmproxy/all.jpeg",
	}
	tests := map[string]imageCase{
		"empty":                          {nil},
		"undetected text":                {[]byte("flibble")},
		"detected tiff without a parser": {[]byte("MM\x00\x2a")},
		"ico with embedded png": {func() []byte {
			out := []byte{0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 32, 0, 22, 0, 0, 0, 22, 0, 0, 0}
			return append(out, "\x89PNG\r\n\x1a\n"...)
		}()},
		"gif with unknown extension label": {[]byte("GIF89a\x02\x00\x03\x00\x00\x05\x00\x21\x01\x02hi\x00\x3b")},
		"gif with unknown block type":      {[]byte("GIF89a\x02\x00\x03\x00\x00\x05\x00\x01")},
		"jpeg with unknown density unit":   {[]byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x02\x03\x00\x60\x00\x30\x00\x00\xff\xd9")},
		"jpeg comment with invalid utf-8":  {[]byte("\xff\xd8\xff\xfe\x00\x06caf\xe9\xff\xd9")},
		"jpeg with short segment length":   {[]byte("\xff\xd8\xff\xe0\x00\x01")},
	}
	for _, fixture := range fixtures {
		tests["fixture/"+fixture] = imageCase{testutil.Fixture(t, fixture)}
	}
	// Prefixes exercise every truncation point of the smallest fixture of
	// each format and a sample of the larger ones.
	prefixes := map[string]int{
		"mitmproxy/image_parser/ct0n0g04.png": 1,
		"mitmproxy/image_parser/chi.gif":      37,
		"mitmproxy/image_parser/example.jpg":  157,
		"mitmproxy/image.ico":                 29,
	}
	for fixture, stride := range prefixes {
		data := testutil.Fixture(t, fixture)
		for i := 0; i < len(data); i += stride {
			tests[fmt.Sprintf("prefix/%s/%d", fixture, i)] = imageCase{data[:i]}
		}
	}
	// Seeded single-byte mutations cover unexpected values in otherwise
	// well-formed files.
	const seed = 530127
	t.Logf("Image differential seed=%d", seed)
	rng := rand.New(rand.NewPCG(seed, 0))
	mutations := map[string]int{
		"mitmproxy/image_parser/ct1n0g04.png": 200,
		"mitmproxy/image_parser/ctzn0g04.png": 100,
		"mitmproxy/image_parser/chi.gif":      200,
		"mitmproxy/image_parser/example.jpg":  200,
		"mitmproxy/image_parser/app1.jpeg":    200,
		"mitmproxy/image.ico":                 100,
	}
	for fixture, count := range mutations {
		data := testutil.Fixture(t, fixture)
		for i := range count {
			mutated := append([]byte{}, data...)
			mutated[rng.IntN(len(mutated))] = byte(rng.IntN(256))
			tests[fmt.Sprintf("mutation/%s/%d", fixture, i)] = imageCase{mutated}
		}
	}
	input, err := json.Marshal(tests)
	if err != nil {
		t.Fatal(err)
	}
	// Alongside the rendered text, the script returns the merged metadata
	// the view rendered, computed the way view.py computes it, because
	// ruamel's own output does not always load back to the values it was
	// given (wrapping a long double-quoted scalar inserts a fold space,
	// and a next-line character in a plain scalar loads back as a space).
	output := difftest.Python(t, `
import base64
import json
import sys
from mitmproxy.contentviews import Metadata
from mitmproxy.contentviews._utils import merge_repeated_keys
from mitmproxy.contentviews._view_image import image
from mitmproxy.contentviews._view_image import image_parser
from mitmproxy.contrib import imghdr
result = {}
for name, case in json.load(sys.stdin).items():
    data = base64.b64decode(case["data"] or "")
    try:
        text = image.prettify(data, Metadata())
        image_type = imghdr.what("", h=data)
        if image_type == "png":
            pairs = image_parser.parse_png(data)
        elif image_type == "gif":
            pairs = image_parser.parse_gif(data)
        elif image_type == "jpeg":
            pairs = image_parser.parse_jpeg(data)
        elif image_type == "ico":
            pairs = image_parser.parse_ico(data)
        else:
            pairs = []
        result[name] = {"text": text, "merged": merge_repeated_keys(pairs)}
    except Exception as exc:
        result[name] = {"error": type(exc).__name__}
json.dump(result, sys.stdout)
`, input)
	var reference map[string]struct {
		Text   *string        `json:"text"`
		Merged map[string]any `json:"merged"`
		Error  string         `json:"error"`
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
			got, err := (Image{}).Prettify(tt.Data, Metadata{})
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
				// go-yaml lays out and escapes scalars differently from
				// ruamel. Permit a different spelling of the same values:
				// the heading must match exactly, and the YAML below it
				// must decode to the metadata the Python view rendered.
				wantHeading, _, _ := strings.Cut(*ref.Text, "\n")
				gotHeading, gotYAML, _ := strings.Cut(got, "\n")
				if wantHeading != gotHeading {
					t.Fatalf("input=%q; Go/Python difference (-Python +Go):\n%s", tt.Data, diff)
				}
				var gotValue any
				if err := yaml.Load([]byte(gotYAML), &gotValue); err != nil {
					t.Fatalf("Go text %q does not load: %v", got, err)
				}
				if diff := cmp.Diff(any(ref.Merged), gotValue); diff != "" {
					t.Fatalf("input=%q; Go text decodes away from Python's metadata (-Python +Go):\n%s", tt.Data, diff)
				}
			}
		})
	}
}
