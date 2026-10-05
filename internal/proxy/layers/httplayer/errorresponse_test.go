// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"strconv"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/version"
)

func TestFormatError(t *testing.T) {
	t.Parallel()

	// Expected bodies are mitmproxy's format_error output
	// (mitmproxy/proxy/layers/http/_base.py), byte for byte.
	tests := map[string]struct {
		statusCode int
		message    string
		want       string
	}{
		"success: known reason with escaping": {
			statusCode: 502,
			message:    `<script>&'"`,
			want: "<html>\n<head>\n    <title>502 Bad Gateway</title>\n</head>\n<body>\n" +
				"    <h1>502 Bad Gateway</h1>\n    <p>&lt;script&gt;&amp;&#x27;&quot;</p>\n</body>\n</html>",
		},
		"success: body size limit message": {
			statusCode: 413,
			message:    "Request body exceeds mitmproxy's body_size_limit.",
			want: "<html>\n<head>\n    <title>413 Payload Too Large</title>\n</head>\n<body>\n" +
				"    <h1>413 Payload Too Large</h1>\n    <p>Request body exceeds mitmproxy&#x27;s body_size_limit.</p>\n</body>\n</html>",
		},
		"success: unknown status code": {
			statusCode: 999,
			message:    "",
			want: "<html>\n<head>\n    <title>999 Unknown</title>\n</head>\n<body>\n" +
				"    <h1>999 Unknown</h1>\n    <p></p>\n</body>\n</html>",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if diff := gocmp.Diff(tt.want, string(formatError(tt.statusCode, tt.message))); diff != "" {
				t.Errorf("FormatError (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMakeErrorResponse(t *testing.T) {
	t.Parallel()

	response, err := makeErrorResponse(502, "Connection failed")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 502 || response.Reason != "Bad Gateway" || response.HTTPVersion != "HTTP/1.1" {
		t.Fatalf("status line = %d %q %q", response.StatusCode, response.Reason, response.HTTPVersion)
	}
	if diff := gocmp.Diff(string(formatError(502, "Connection failed")), string(response.RawContent)); diff != "" {
		t.Fatal(diff)
	}
	want := map[string]string{
		"Server":       version.String(),
		"Connection":   "close",
		"Content-Type": "text/html",
	}
	for name, value := range want {
		if got := response.Headers.Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
	if got, want := response.Headers.Get("Content-Length"), strconv.Itoa(len(response.RawContent)); got != want {
		t.Errorf("Content-Length = %q, want %q", got, want)
	}
}
