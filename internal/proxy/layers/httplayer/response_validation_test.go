// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"io"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
)

const ambiguousResponseError = "Received message with both transfer-encoding and content-length headers from server, refusing to prevent request smuggling attacks. Disable the validate_inbound_headers option to skip this security check."

func TestStreamResponseValidation(t *testing.T) {
	tests := map[string]struct {
		status int
	}{
		"error: final response":      {status: 200},
		"error: switching protocols": {status: 101},
		"error: informational head":  {status: 103},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := &streamAddon{}
			s, _ := newTestStream(t, a)
			s.route.validateInboundHeaders = true
			drainStream(t, s, requestHead("0"))
			drainStream(t, s, RequestEndOfMessage{ID: 1})
			response := &httpmsg.Response{
				HTTPVersion: "HTTP/1.1", StatusCode: tt.status,
				Headers: httpmsg.Headers{
					{Name: []byte("Transfer-Encoding"), Value: []byte("chunked")},
					{Name: []byte("Content-Length"), Value: []byte("42")},
				},
			}
			out, err := s.handle(t.Context(), ResponseHeaders{ID: 1, Response: response})
			if err != nil {
				t.Fatal(err)
			}
			want := []Event{RequestProtocolError{ID: 1, Message: ambiguousResponseError, Code: ResponseValidationFailed}}
			if diff := gocmp.Diff(want, out.events); diff != "" {
				t.Fatalf("retire origin before error hook (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff([]string{"requestheaders", "request"}, a.calls); diff != "" {
				t.Fatalf("hooks before origin retirement (-want +got):\n%s", diff)
			}
			if out.after == nil {
				t.Fatal("missing error-hook continuation")
			}
			out, err = out.after(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			want = []Event{ResponseProtocolError{ID: 1, Message: ambiguousResponseError, Code: ResponseValidationFailed}}
			if diff := gocmp.Diff(want, out.events); diff != "" {
				t.Fatalf("validation failure (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff([]string{"requestheaders", "request", "error"}, a.calls); diff != "" {
				t.Fatalf("hooks (-want +got):\n%s", diff)
			}
			if s.flow.Response != response || s.flow.Error == nil || s.flow.Error.Msg != ambiguousResponseError || s.flow.Live {
				t.Fatalf("rejected flow: response=%p, error=%v, live=%v", s.flow.Response, s.flow.Error, s.flow.Live)
			}
			if !s.done() || !s.failed {
				t.Fatal("invalid response did not terminate the stream")
			}
		})
	}
}

// Upstream test_request_smuggling_response rejects an ambiguous response head
// before forwarding it or calling responseheaders, and retires the origin first.
func TestLayerResponseValidation(t *testing.T) {
	tests := map[string]struct {
		validate bool
	}{
		"error: validation rejects ambiguous framing": {validate: true},
		"success: disabled validation forwards":       {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var received *flow.HTTPFlow
			var responseAtError *httpmsg.Response
			a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				received = f
				if name == "error" && f.Response != nil {
					responseAtError = f.Response.Clone()
				}
			}}
			option := "validate_inbound_headers=false"
			if tt.validate {
				option = "validate_inbound_headers=true"
			}
			s := newLayerSession(t, a, "connection_strategy=lazy", option)
			s.start(hookdata.HTTPModeRegular)
			write(t, s.client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
			origin := await(t, s.pool.origins)
			expectRead(t, origin, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
			head := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 42\r\nConnection: close\r\n\r\n"
			body := ""
			if !tt.validate {
				body = "0\r\n\r\n"
			}
			write(t, origin, head+body)
			data, err := io.ReadAll(s.client)
			if err != nil {
				t.Fatal(err)
			}
			if err := await(t, s.done); err != nil {
				t.Fatal(err)
			}
			if tt.validate {
				if !strings.HasPrefix(string(data), "HTTP/1.1 502 Bad Gateway\r\n") || !strings.Contains(string(data), ambiguousResponseError) {
					t.Fatalf("validation response = %q, want 502 with %q", data, ambiguousResponseError)
				}
				if diff := gocmp.Diff([]string{"requestheaders", "request", "error"}, a.calls); diff != "" {
					t.Fatalf("hooks (-want +got):\n%s", diff)
				}
				if responseAtError == nil || responseAtError.Headers.Get("Content-Length") != "42" || received.Error == nil || received.Error.Msg != ambiguousResponseError {
					t.Fatalf("error hook lost the rejected response: %#v", received)
				}
				if data, err := io.ReadAll(origin); err != nil || len(data) != 0 {
					t.Fatalf("origin retirement = (%q, %v), want EOF", data, err)
				}
			} else {
				if diff := gocmp.Diff(head+"0\r\n\r\n", string(data)); diff != "" {
					t.Fatalf("validation disabled (-want +got):\n%s", diff)
				}
				if diff := gocmp.Diff([]string{"requestheaders", "request", "responseheaders", "response"}, a.calls); diff != "" {
					t.Fatalf("hooks (-want +got):\n%s", diff)
				}
			}
		})
	}
}
