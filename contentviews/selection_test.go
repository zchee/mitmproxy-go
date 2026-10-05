// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

// TestViewSelection ports upstream's test_view_selection and extends the
// table to every built-in view that can win automatic selection.
func TestViewSelection(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		data     []byte
		metadata Metadata
		want     string
	}{
		"success: plain text falls back to raw": {
			data: []byte("foo"),
			want: "Raw",
		},
		"success: html content type selects xml/html": {
			data:     []byte("<html></html>"),
			metadata: Metadata{ContentType: "text/html"},
			want:     "XML/HTML",
		},
		"success: unknown content type falls back to raw": {
			data:     []byte("foo"),
			metadata: Metadata{ContentType: "text/flibble"},
			want:     "Raw",
		},
		"success: xml sniffed under an unknown content type": {
			data:     []byte("<xml></xml>"),
			metadata: Metadata{ContentType: "text/flibble"},
			want:     "XML/HTML",
		},
		"success: svg selects xml/html, not image": {
			data:     []byte("<svg></svg>"),
			metadata: Metadata{ContentType: "image/svg+xml"},
			want:     "XML/HTML",
		},
		"success: json structured suffix": {
			data:     []byte("{}"),
			metadata: Metadata{ContentType: "application/acme+json"},
			want:     "JSON",
		},
		"success: unknown image format still selects image": {
			data:     []byte("verybinary"),
			metadata: Metadata{ContentType: "image/new-magic-image-format"},
			want:     "Image",
		},
		"success: binary data selects the hex dump": {
			data: bytes.Repeat([]byte{0xff}, 30),
			want: "Hex Dump",
		},
		"success: empty body falls back to raw": {
			data: []byte{},
			want: "Raw",
		},
		"success: form body selects url-encoded": {
			data:     []byte("one=two&three=four"),
			metadata: Metadata{ContentType: "application/x-www-form-urlencoded"},
			want:     "URL-encoded",
		},
		"success: multipart body selects the multipart form": {
			data:     []byte("--boundary\r\n"),
			metadata: Metadata{ContentType: "multipart/form-data"},
			want:     "Multipart Form",
		},
		"success: style sheet selects css": {
			data:     []byte("#foo{color:red}"),
			metadata: Metadata{ContentType: "text/css"},
			want:     "ViewCSS",
		},
		"success: text/javascript selects javascript": {
			data:     []byte("var x=1;"),
			metadata: Metadata{ContentType: "text/javascript"},
			want:     "JavaScript",
		},
		"success: application/javascript selects javascript": {
			data:     []byte("var x=1;"),
			metadata: Metadata{ContentType: "application/javascript"},
			want:     "JavaScript",
		},
		"success: application/x-javascript selects javascript": {
			data:     []byte("var x=1;"),
			metadata: Metadata{ContentType: "application/x-javascript"},
			want:     "JavaScript",
		},
		"success: png selects image": {
			data:     []byte("\x89PNG\r\n\x1a\n"),
			metadata: Metadata{ContentType: "image/png"},
			want:     "Image",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := NewRegistry().GetView(tt.data, tt.metadata, "auto")
			if err != nil {
				t.Fatalf("GetView() error = %v", err)
			}
			if got.Name() != tt.want {
				t.Fatalf("GetView() selected %q, want %q", got.Name(), tt.want)
			}
		})
	}
	t.Run("success: empty body with request query selects query", func(t *testing.T) {
		t.Parallel()
		request := testflow.TReq()
		request.Path = "/path?a=b"
		got, err := NewRegistry().GetView(nil, Metadata{HTTPRequest: request}, "auto")
		if err != nil {
			t.Fatalf("GetView() error = %v", err)
		}
		if got.Name() != "Query" {
			t.Fatalf("GetView() selected %q, want %q", got.Name(), "Query")
		}
	})
}
