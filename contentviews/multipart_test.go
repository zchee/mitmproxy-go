// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

// multipartBody is the body of upstream's test_view_multipart.
const multipartBody = "--AaB03x\r\nContent-Disposition: form-data; name=\"submit-name\"\r\n\r\nLarry\r\n--AaB03x"

// TestMultipart ports test_view_multipart and test_render_priority, adding
// repeated names, escaped bytes, and the undelimited-part error.
func TestMultipart(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		contentType string
		data        string
		missing     bool
		noHeader    bool
		want        string
		wantErr     string
	}{
		"success: form value": {
			contentType: "multipart/form-data; boundary=AaB03x",
			data:        multipartBody,
			want:        "submit-name: Larry\n",
		},
		"error: missing message": {
			missing: true,
			data:    multipartBody,
			wantErr: "Not an HTTP message",
		},
		"error: missing content type header": {
			noHeader: true,
			data:     multipartBody,
			wantErr:  "content-type header is missing",
		},
		"success: no boundary": {
			contentType: "multipart/form-data",
			data:        multipartBody,
			want:        "",
		},
		"success: unparseable content type": {
			contentType: "unparseable",
			data:        multipartBody,
			want:        "",
		},
		"success: empty body": {
			contentType: "multipart/form-data; boundary=AaB03x",
			want:        "",
		},
		"success: repeated names merge": {
			contentType: "multipart/form-data; boundary=b",
			data: "--b\r\nContent-Disposition: form-data; name=\"k\"\r\n\r\nfirst\r\n" +
				"--b\r\nContent-Disposition: form-data; name=\"k\"\r\n\r\nsecond\r\n--b--",
			want: "k:\n- first\n- second\n",
		},
		"success: escaped bytes": {
			contentType: "multipart/form-data; boundary=b",
			data:        "--b\r\nContent-Disposition: form-data; name=\"k\"\r\n\r\nval\xffue\r\n--b--",
			want:        "k: val\\xffue\n",
		},
		"error: part without blank line": {
			contentType: "multipart/form-data; boundary=b",
			data:        "--b\r\nContent-Disposition: form-data; name=\"k\"\r\nLarry\r\n--b--",
			wantErr:     "multipart part has no end of headers",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var metadata Metadata
			if !tt.missing {
				request := testflow.TReq()
				request.Headers = httpmsg.Headers{}
				if !tt.noHeader {
					request.Headers.Set("content-type", tt.contentType)
					metadata.ContentType, _, _ = strings.Cut(tt.contentType, ";")
				}
				metadata.HTTPMessage = &request.Message
			}
			got, err := (Multipart{}).Prettify([]byte(tt.data), metadata)
			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}
			if diff := cmp.Diff(tt.wantErr, gotErr); diff != "" {
				t.Fatalf("error (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("text (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMultipartRenderPriority(t *testing.T) {
	t.Parallel()
	view := Multipart{}
	if got := view.RenderPriority([]byte("data"), Metadata{ContentType: "multipart/form-data"}); got != 1 {
		t.Fatalf("priority = %v, want 1", got)
	}
	if got := view.RenderPriority([]byte("data"), Metadata{ContentType: "text/plain"}); got != 0 {
		t.Fatalf("priority = %v, want 0", got)
	}
	if got := view.RenderPriority(nil, Metadata{ContentType: "multipart/form-data"}); got != 0 {
		t.Fatalf("priority = %v, want 0", got)
	}
}

func TestMultipartMessage(t *testing.T) {
	t.Parallel()
	request := testflow.TReq()
	request.Headers = httpmsg.Headers{}
	request.Headers.Set("content-type", "multipart/form-data; boundary=AaB03x")
	request.SetContent([]byte(multipartBody))
	got := PrettifyMessage(request, nil, "auto", nil, 0)
	want := Result{Text: "submit-name: Larry\n", SyntaxHighlight: "yaml", ViewName: "Multipart Form"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("message (-want +got):\n%s", diff)
	}
}
