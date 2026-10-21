// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package style

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

func verifyFlowRowStyles(t *testing.T) {
	t.Helper()
	row := contract.Row{Type: "http", Method: "GET", Scheme: "https", Host: "www.example.com", Path: "/dir/file.json?key=value&other=yes", URL: "https://www.example.com/dir/file.json?key=value&other=yes", HTTPVersion: "HTTP/1.1", HasResponse: true, StatusCode: 200, ContentType: "application/json", Size: 1234, Duration: .1, Timestamp: 1600000000, Marked: ":red_circle:", Replay: "request"}
	tests := map[string]struct {
		method, content, methodTag, contentTag string
	}{
		"get data":    {"GET", "application/json", "method_get", "content_data"},
		"post script": {"POST", "application/javascript", "method_post", "content_script"},
		"delete text": {"DELETE", "text/plain", "method_delete", "content_text"},
		"head media":  {"HEAD", "image/png", "method_head", "content_media"},
		"put raw":     {"PUT", "application/octet-stream", "method_put", "content_raw"},
		"other":       {"PATCH", "unknown", "method_other", "content_other"},
	}
	for _, name := range Names() {
		palette, err := NewPalette(name, true)
		if err != nil {
			t.Fatal(err)
		}
		if got := flowPaint(&palette, "text", ""); got != "" {
			t.Fatalf("%s emitted a zero-width style span: %q", name, got)
		}
		for label, test := range tests {
			candidate := row
			candidate.Method, candidate.ContentType = test.method, test.content
			for _, layout := range []string{"table", "list", "detailview"} {
				for _, width := range []int{0, 10, 80, 100, 200, 300} {
					candidate.Text = formatHTTPRow(candidate, layout, width, true, nil)
					got := RenderFlowRow(candidate, layout, width, true, palette)
					if diff := cmp.Diff(candidate.Text, ansi.Strip(got)); diff != "" {
						t.Fatalf("%s/%s layout=%s width=%d changed text: %s", name, label, layout, width, diff)
					}
					if layout == "table" && width == 300 {
						for tag, token := range map[string]string{test.methodTag: Fit(test.method, 4), test.contentTag: test.content, "code_200": "200", "focus": ">>", "mark": "●", "replay": "↺", "url_punctuation": "/", "url_filename": "file", "url_query_key": "key", "url_query_value": "value"} {
							if !strings.Contains(got, palette.Style(tag).Render(token)) {
								t.Errorf("%s/%s missing %s token %q: %q", name, label, tag, token, got)
							}
						}
					}
				}
			}
		}
		for _, intercepted := range []bool{true, false} {
			for _, response := range []bool{true, false} {
				candidate := row
				candidate.Intercepted, candidate.HasResponse = intercepted, response
				candidate.Error = "failed\\x1b[2J"
				candidate.Path = "/日本語/é.txt?q=値"
				for _, layout := range []string{"table", "list"} {
					candidate.Text = formatHTTPRow(candidate, layout, 200, false, nil)
					if diff := cmp.Diff(candidate.Text, ansi.Strip(RenderFlowRow(candidate, layout, 200, false, palette))); diff != "" {
						t.Fatal(diff)
					}
				}
			}
		}
	}
}
