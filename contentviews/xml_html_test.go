// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/httpmsg"
)

// TestXMLHTML ports test__view_xml_html.py's simple and message-text cases.
func TestXMLHTML(t *testing.T) {
	tests := map[string]struct {
		data    string
		message *httpmsg.Message
		want    string
	}{
		"test_simple text":                  {"foo", nil, "foo\n"},
		"test_simple inline":                {"<html></html>", nil, "<html></html>\n"},
		"test_simple empty tag":             {"<>", nil, "<>\n"},
		"test_simple incomplete tag":        {"<p", nil, "<p\n"},
		"test_use_text bytes":               {"\xf8", nil, "\\xf8\n"},
		"test_use_text message":             {"\xf8", &httpmsg.Message{RawContent: []byte{0xf8}}, "ø\n"},
		"empty":                             {"", nil, ""},
		"empty HTTP message overrides data": {"data", &httpmsg.Message{}, ""},
		"inline text":                       {"<p> foo </p>", nil, "<p>foo</p>\n"},
		"mismatched closing tag":            {"<a><b></a></b>", nil, "<a>\n  <b>\n</a>\n</b>\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := (XMLHTML{}).Prettify([]byte(tt.data), Metadata{HTTPMessage: tt.message})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// TestXMLTokens covers test_simple's token assertion; Go tokens have no Python repr.
func TestXMLTokens(t *testing.T) {
	tests := map[string]struct {
		input string
		want  []string
	}{
		"doctype":       {"<!DOCTYPE html>", []string{"<!DOCTYPE html>"}},
		"text and tags": {"<p> text </p>", []string{"<p>", " text ", "</p>"}},
		"comment":       {"<!-- a > b -->", []string{"<!-- a > b -->"}},
		"CDATA":         {"<![CDATA[a > b]]>", []string{"<![CDATA[a > b]]>"}},
		"incomplete":    {"<p", []string{"<p"}},
		"whitespace":    {" \t\n", nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var got []string
			for token := range xmlTokens(tt.input) {
				got = append(got, token.data)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestXMLHTMLFixtures(t *testing.T) {
	tests := map[string]struct{ filename string }{
		"test_format_xml simple":  {"simple.html"},
		"test_format_xml cdata":   {"cdata.xml"},
		"test_format_xml comment": {"comment.xml"},
		"test_format_xml inline":  {"inline.html"},
		"test_format_xml test":    {"test.html"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			path := "testdata/xml_html/" + tt.filename
			input, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			base, ext, _ := strings.CutLast(path, ".")
			want, err := os.ReadFile(base + "-formatted." + ext)
			if err != nil {
				t.Fatal(err)
			}
			got, err := (XMLHTML{}).Prettify(input, Metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(string(want), got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestXMLHTMLRenderPriority(t *testing.T) {
	tests := map[string]struct {
		data        string
		contentType string
		want        float64
	}{
		"text/xml":   {"data", "text/xml", 1},
		"text/html":  {"data", "text/html", 1},
		"text/plain": {"data", "text/plain", 0},
		"empty":      {"", "text/xml", 0},
		"sniff":      {"<html/>", "", 0.4},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := (XMLHTML{}).RenderPriority([]byte(tt.data), Metadata{ContentType: tt.contentType})
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
