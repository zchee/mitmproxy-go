// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/httpmsg"
)

// Upstream test_http2.py: test_split_pseudo_headers and test_split_pseudo_headers_err.
func TestSplitH2PseudoHeaders(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		input   []hpack.HeaderField
		pseudo  map[string]string
		headers httpmsg.Headers
		wantErr string
	}{
		"success: regular fields only": {
			input: []hpack.HeaderField{{Name: "foo", Value: "bar"}}, pseudo: map[string]string{},
			headers: httpmsg.Headers{{Name: []byte("foo"), Value: []byte("bar")}},
		},
		"success: pseudo fields only": {
			input: []hpack.HeaderField{{Name: ":status", Value: "418"}}, pseudo: map[string]string{":status": "418"}, headers: httpmsg.Headers{},
		},
		"success: ordered duplicate regular fields": {
			input:   []hpack.HeaderField{{Name: ":status", Value: "418"}, {Name: "foo", Value: "bar"}, {Name: "foo", Value: "second"}},
			pseudo:  map[string]string{":status": "418"},
			headers: httpmsg.Headers{{Name: []byte("foo"), Value: []byte("bar")}, {Name: []byte("foo"), Value: []byte("second")}},
		},
		"error: duplicate pseudo header": {
			input: []hpack.HeaderField{{Name: ":status", Value: "418"}, {Name: ":status", Value: "418"}}, wantErr: "Duplicate HTTP/2 pseudo header: b':status'",
		},
		"success: validation bypass preserves a late pseudo field": {
			input: []hpack.HeaderField{{Name: "foo", Value: "bar"}, {Name: ":status", Value: "418"}}, pseudo: map[string]string{},
			headers: httpmsg.Headers{{Name: []byte("foo"), Value: []byte("bar")}, {Name: []byte(":status"), Value: []byte("418")}},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pseudo, headers, err := splitH2PseudoHeaders(tt.input)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("split error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.pseudo, pseudo); diff != "" {
				t.Errorf("pseudo headers (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(tt.headers, headers); diff != "" {
				t.Errorf("headers (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseH2RequestHeaders(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		fields    []hpack.HeaderField
		host      string
		port      int
		authority string
		wantErr   string
	}{
		"success: https default port":                          {authority: "example.com", host: "example.com", port: 443},
		"success: IPv6 explicit port":                          {authority: "[::1]:8443", host: "::1", port: 8443},
		"success: absent authority leaves routing to the mode": {},
		"error: duplicate method":                              {fields: []hpack.HeaderField{{Name: ":method", Value: "POST"}}, wantErr: "Duplicate HTTP/2 pseudo header: b':method'"},
		"error: unknown pseudo headers preserve their order": {
			fields:  []hpack.HeaderField{{Name: ":extra", Value: "one"}, {Name: ":other", Value: "two"}},
			wantErr: "Unknown pseudo headers: {b':extra': b'one', b':other': b'two'}",
		},
		"error: invalid authority": {authority: "[bad", wantErr: "invalid authority"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fields := []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/?query"}}
			if tt.authority != "" {
				fields = append(fields, hpack.HeaderField{Name: ":authority", Value: tt.authority})
			}
			fields = append(fields, tt.fields...)
			request, err := parseH2RequestHeaders(fields)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parse error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := &httpmsg.Request{HTTPVersion: "HTTP/2.0", Headers: httpmsg.Headers{}, Method: "GET", Scheme: "https", Path: "/?query", Authority: tt.authority, Host: tt.host, Port: tt.port}
			if diff := gocmp.Diff(want, request); diff != "" {
				t.Errorf("request (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseH2RequiredPseudoHeaders(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		fields  []hpack.HeaderField
		request bool
		wantErr string
	}{
		"error: method missing":          {request: true, wantErr: "Required pseudo header is missing: b':method'"},
		"error: CONNECT scheme missing":  {request: true, fields: []hpack.HeaderField{{Name: ":method", Value: "CONNECT"}, {Name: ":authority", Value: "example.com:443"}}, wantErr: "Required pseudo header is missing: b':scheme'"},
		"error: request path missing":    {request: true, fields: []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}}, wantErr: "Required pseudo header is missing: b':path'"},
		"error: response status missing": {wantErr: "Required pseudo header is missing: b':status'"},
		"error: invalid response status": {fields: []hpack.HeaderField{{Name: ":status", Value: "oops"}}, wantErr: "invalid literal for int() with base 10: b'oops'"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var err error
			if tt.request {
				_, err = parseH2RequestHeaders(tt.fields)
			} else {
				_, err = parseH2ResponseHeaders(tt.fields)
			}
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("parse error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// Upstream test_http2.py: test_no_normalization; h1 conversion follows hyper-h2 utilities.
func TestFormatH2Headers(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		version   string
		normalize bool
		headers   httpmsg.Headers
		want      []hpack.HeaderField
		wantLog   string
	}{
		"success: h2 validation bypass preserves bytes and order": {
			version: "HTTP/2.0", headers: httpmsg.Headers{{Name: []byte("Same"), Value: []byte(" Here ")}, {Name: []byte("Same"), Value: []byte("second")}},
			want: []hpack.HeaderField{{Name: "Same", Value: " Here "}, {Name: "Same", Value: "second"}},
		},
		"success: h2 normalization logs without trimming values": {
			version: "HTTP/2.0", normalize: true, headers: httpmsg.Headers{{Name: []byte("Same"), Value: []byte(" Here ")}},
			want: []hpack.HeaderField{{Name: "same", Value: " Here "}}, wantLog: "Lowercased 'Same' header as uppercase is not allowed with HTTP/2.",
		},
		"success: h3 normalization also applies": {
			version: "HTTP/3", normalize: true, headers: httpmsg.Headers{{Name: []byte("Same"), Value: []byte("Here")}},
			want: []hpack.HeaderField{{Name: "same", Value: "Here"}}, wantLog: "Lowercased 'Same' header as uppercase is not allowed with HTTP/2.",
		},
		"success: h1 conversion is unconditional and removes connection fields": {
			version: "HTTP/1.1", headers: httpmsg.Headers{{Name: []byte(" Connection "), Value: []byte("close")}, {Name: []byte("Transfer-Encoding"), Value: []byte("chunked")}, {Name: []byte("Same"), Value: []byte(" Here ")}},
			want: []hpack.HeaderField{{Name: "same", Value: "Here"}},
		},
		"success: h1 sensitive fields use never indexed HPACK": {
			version: "HTTP/1.1", headers: httpmsg.Headers{{Name: []byte("Authorization"), Value: []byte("Basic abc")}, {Name: []byte("Cookie"), Value: []byte("x=y")}},
			want: []hpack.HeaderField{{Name: "authorization", Value: "Basic abc", Sensitive: true}, {Name: "cookie", Value: "x=y", Sensitive: true}},
		},
		"success: bypass retains non-ASCII name bytes": {
			version: "HTTP/2.0", normalize: true, headers: httpmsg.Headers{{Name: []byte("Ä-X"), Value: []byte("v")}},
			want: []hpack.HeaderField{{Name: "Ä-x", Value: "v"}}, wantLog: "header as uppercase is not allowed with HTTP/2.",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			response := &httpmsg.Response{HTTPVersion: tt.version, Headers: tt.headers, StatusCode: 200}
			before := response.Clone()
			got := formatH2ResponseHeaders(response, tt.normalize, logger)
			want := append([]hpack.HeaderField{{Name: ":status", Value: "200"}}, tt.want...)
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Errorf("wire fields (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(before, response); diff != "" {
				t.Errorf("formatter mutated message (-want +got):\n%s", diff)
			}
			if tt.wantLog != "" && !strings.Contains(logs.String(), tt.wantLog) {
				t.Errorf("log = %q, want %q", logs.String(), tt.wantLog)
			} else if tt.wantLog == "" && logs.Len() != 0 {
				t.Errorf("unexpected normalization log: %s", logs.String())
			}
		})
	}
}
