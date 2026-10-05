// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

// TestQuery ports test_view_query and test_render_priority, including malformed
// query escapes, empty fields, and explicit rendering when a body is present.
func TestQuery(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		path     string
		data     string
		missing  bool
		want     string
		wantErr  string
		priority float64
	}{
		"error: missing request":             {missing: true, wantErr: "Not an HTTP request."},
		"success: repeated keys":             {path: "/?foo=bar&foo=baz", want: "foo:\n- bar\n- baz\n", priority: 0.3},
		"success: empty query":               {path: "/", want: ""},
		"success: only separators":           {path: "/?&&", want: ""},
		"success: empty values":              {path: "/?a=&a=next&b&=empty", want: "a: next\nb: ''\n'': empty\n", priority: 0.3},
		"success: body ignored":              {path: "/?foo=bar", data: "body", want: "foo: bar\n"},
		"success: malformed percent escapes": {path: "/?a=%&b=%2&c=%xy", want: "a: '%'\nb: '%2'\nc: '%xy'\n", priority: 0.3},
		"success: invalid octet string":      {path: "/?a=%FF", want: "a: \"\x5cuDCFF\"\n", priority: 0.3},
		"success: NEL preserved":             {path: "/?a=a%C2%85b", want: "a: \"a\\Nb\"\n", priority: 0.3},
		"success: Unicode text":              {path: "/?name=%E6%97%A5%E6%9C%AC%E8%AA%9E", want: "name: 日本語\n", priority: 0.3},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			metadata := Metadata{HTTPMessage: &httpmsg.Message{}}
			if !tt.missing {
				metadata.HTTPRequest = testflow.TReq()
				metadata.HTTPRequest.Path = tt.path
			}
			view := Query{}
			got, err := view.Prettify([]byte(tt.data), metadata)
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
			if got := view.RenderPriority([]byte(tt.data), metadata); got != tt.priority {
				t.Fatalf("priority = %v, want %v", got, tt.priority)
			}
		})
	}
}

func TestQueryMessage(t *testing.T) {
	t.Parallel()
	request := testflow.TReq()
	request.Path = "/?foo=bar&foo=baz"
	request.SetContent([]byte{})
	got := PrettifyMessage(request, nil, "auto", nil, 0)
	want := Result{Text: "foo:\n- bar\n- baz\n", SyntaxHighlight: "yaml", ViewName: "Query"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("message (-want +got):\n%s", diff)
	}
}
