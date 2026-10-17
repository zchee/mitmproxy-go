// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestWBXML(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]func(*testing.T){
			"test_wbxml": func(t *testing.T) {
				view := WBXML{}
				text, err := view.Prettify([]byte{3, 1, 0x6a, 0}, Metadata{})
				if err != nil || text != "<?xml version=\"1.0\" ?>\n" {
					t.Fatalf("minimal document=%q %v", text, err)
				}
				if _, err := view.Prettify([]byte("foo"), Metadata{}); err == nil {
					t.Fatal("invalid WBXML accepted")
				}
				data, err := os.ReadFile("../testdata/mitmproxy/contentviews/test_wbxml_data/data.wbxml")
				if err != nil {
					t.Fatal(err)
				}
				want, err := os.ReadFile("../testdata/mitmproxy/contentviews/test_wbxml_data/data-formatted.wbxml")
				if err != nil {
					t.Fatal(err)
				}
				text, err = view.Prettify(data, Metadata{})
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(string(want), text); diff != "" {
					t.Fatal(diff)
				}
			},
			"test_render_priority": func(t *testing.T) {
				view := WBXML{}
				for _, media := range []string{"application/vnd.wap.wbxml", "application/vnd.ms-sync.wbxml"} {
					if view.RenderPriority([]byte("data"), Metadata{ContentType: media}) != 1 {
						t.Errorf("missing priority for %s", media)
					}
				}
				if view.RenderPriority([]byte("data"), Metadata{ContentType: "text/plain"}) != 0 {
					t.Fatal("plain text selected as WBXML")
				}
			},
		}
		for name, test := range tests {
			t.Run(name, test)
		}
	})
}

func TestWBXMLTables(t *testing.T) {
	hash := sha256.New()
	count := 0
	for page, tokens := range wbxmlCodePages {
		for token, name := range tokens {
			if name != "" {
				if _, err := fmt.Fprintf(hash, "%d:%d:%s\n", page, token, name); err != nil {
					t.Fatal(err)
				}
				count++
			}
		}
	}
	if count != 535 || fmt.Sprintf("%x", hash.Sum(nil)) != "7cdfd4dabffa8d2c6cd42fc1cba0d42c1f90d5ec97edf7e70cdfb0d013e2c055" {
		t.Fatal("WBXML vocabulary differs from the pinned source")
	}
}

func TestWBXMLAdditional(t *testing.T) {
	tests := map[string]struct {
		body []byte
		want string
	}{
		"page switch": {[]byte{0, 1, 5}, "<Anniversary/>\n"},
		"empty tag":   {[]byte{5}, "<Sync/>\n"},
		"text":        {[]byte{0x45, 3, 'a', '&', '<', '>', '"', 0, 1}, "<Sync>a&amp;&lt;&gt;\"</Sync>\n"},
		"byte text":   {[]byte{0x45, 3, 0xc3, 0xa9, 0, 1}, "<Sync>Ã©</Sync>\n"},
		"cdata":       {[]byte{0x45, 0xc3, 1, 'x', 1}, "<Sync><![CDATA[x]]></Sync>\n"},
		"mixed cdata": {[]byte{0x45, 3, 'a', 0, 0xc3, 1, 'x', 1}, "<Sync>\n    a\n<![CDATA[x]]></Sync>\n"},
		"open at EOF": {[]byte{0x45}, "<Sync/>\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			data := append([]byte{3, 1, 0x6a, 0}, tt.body...)
			text, err := (WBXML{}).Prettify(data, Metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff("<?xml version=\"1.0\" ?>\n"+tt.want, text); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestWBXMLMalformed(t *testing.T) {
	tests := map[string]struct{ data []byte }{
		"empty":            {},
		"header":           {[]byte{3, 1}},
		"charset":          {[]byte{3, 1, 0, 0}},
		"string table":     {[]byte{3, 1, 0x6a, 1}},
		"page truncated":   {[]byte{3, 1, 0x6a, 0, 0}},
		"unknown page":     {[]byte{3, 1, 0x6a, 0, 0, 25}},
		"unknown tag":      {[]byte{3, 1, 0x6a, 0, 0x3f}},
		"attributes":       {[]byte{3, 1, 0x6a, 0, 0x85}},
		"entity":           {[]byte{3, 1, 0x6a, 0, 2}},
		"unmatched end":    {[]byte{3, 1, 0x6a, 0, 1}},
		"inline truncated": {[]byte{3, 1, 0x6a, 0, 0x45, 3, 'x'}},
		"opaque truncated": {[]byte{3, 1, 0x6a, 0, 0x45, 0xc3, 2, 'x'}},
		"integer overflow": {[]byte{3, 1, 0x6a, 0, 0x45, 0xc3, 0xff, 0xff, 0xff, 0xff, 0x7f}},
		"multiple roots":   {[]byte{3, 1, 0x6a, 0, 5, 5}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if text, err := (WBXML{}).Prettify(tt.data, Metadata{}); err == nil || text != "" {
				t.Fatalf("malformed input returned %q %v", text, err)
			}
		})
	}
	deep := append([]byte{3, 1, 0x6a, 0}, bytes.Repeat([]byte{0x45}, newViewBudget("WBXML").limits.Depth+1)...)
	if _, err := (WBXML{}).Prettify(deep, Metadata{}); err == nil {
		t.Fatal("deep document accepted")
	} else if _, ok := errors.AsType[*LimitError](err); !ok {
		t.Fatalf("expected typed depth limit, got %v", err)
	}
	var out strings.Builder
	full := newViewBudget("WBXML")
	full.output = full.limits.OutputBytes
	if err := renderWBXML(&out, &wbxmlNode{tag: "Sync"}, full, 0); err == nil {
		t.Fatal("XML output bypassed budget")
	}
}

func FuzzWBXML(f *testing.F) {
	for _, data := range [][]byte{{3, 1, 0x6a, 0}, {3, 1, 0x6a, 0, 0x45, 3, 'x', 0, 1}, {3, 1, 0x6a, 0, 0x45, 0xc3, 1, 'x', 1}} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		text, err := (WBXML{}).Prettify(data, Metadata{})
		if err == nil && uint64(len(text)) > newViewBudget("WBXML").limits.OutputBytes {
			t.Fatal("XML output exceeds bound")
		}
	})
}
