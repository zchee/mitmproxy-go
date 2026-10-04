// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http

import (
	"errors"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/state"
)

// tReq mirrors upstream's mitmproxy.test.tutils.treq.
func tReq() *Request {
	return &Request{
		HTTPVersion:    "HTTP/1.1",
		Headers:        hdrs("header", "qvalue", "content-length", "7"),
		RawContent:     []byte("content"),
		TimestampStart: 946681200,
		TimestampEnd:   new(946681201.0),
		Host:           "address",
		Port:           22,
		Method:         "GET",
		Scheme:         "http",
		Path:           "/path",
	}
}

// tResp mirrors upstream's mitmproxy.test.tutils.tresp.
func tResp() *Response {
	return &Response{
		HTTPVersion:    "HTTP/1.1",
		Headers:        hdrs("header-response", "svalue", "content-length", "7"),
		RawContent:     []byte("message"),
		TimestampStart: 946681202,
		TimestampEnd:   new(946681203.0),
		StatusCode:     200,
		Reason:         "OK",
	}
}

var (
	requestKeys = []string{
		"http_version", "headers", "content", "trailers", "timestamp_start", "timestamp_end",
		"host", "port", "method", "scheme", "authority", "path",
	}
	responseKeys = []string{
		"http_version", "headers", "content", "trailers", "timestamp_start", "timestamp_end",
		"status_code", "reason",
	}
)

// fixtureRequestState is the request of the flow format 21 fixture
// corrupted_gzip_body.mitm, in get_state order.
func fixtureRequestState() *state.Map {
	m := state.NewMap(12)
	m.Set("http_version", []byte("HTTP/1.1"))
	m.Set("headers", []any{
		[]any{[]byte("Host"), []byte("127.0.0.1:5000")},
		[]any{[]byte("User-Agent"), []byte("curl/8.11.0")},
		[]any{[]byte("Accept"), []byte("*/*")},
	})
	m.Set("content", []byte{})
	m.Set("trailers", nil)
	m.Set("timestamp_start", 1731596382.2106874)
	m.Set("timestamp_end", 1731596382.2201993)
	m.Set("host", "127.0.0.1")
	m.Set("port", int64(5000))
	m.Set("method", []byte("GET"))
	m.Set("scheme", []byte("http"))
	m.Set("authority", []byte{})
	m.Set("path", []byte("/"))
	return m
}

// fixtureResponseState is the response of corrupted_gzip_body.mitm.
func fixtureResponseState() *state.Map {
	m := state.NewMap(8)
	m.Set("http_version", []byte("HTTP/1.1"))
	m.Set("headers", []any{
		[]any{[]byte("Server"), []byte("Werkzeug/3.0.4 Python/3.12.7")},
		[]any{[]byte("Date"), []byte("Thu, 14 Nov 2024 14:59:42 GMT")},
	})
	m.Set("content", []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03!>\x123A\x0f\xf8\x93\xea\xee\x04\x00\x00\x00"))
	m.Set("trailers", nil)
	m.Set("timestamp_start", 1731596382.2251546)
	m.Set("timestamp_end", 1731596382.2281084)
	m.Set("status_code", int64(200))
	m.Set("reason", []byte("OK"))
	return m
}

type stateful interface{ GetState() *state.Map }

func TestStateKeyOrder(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		got  stateful
		want []string
	}{
		"success: request":       {got: tReq(), want: requestKeys},
		"success: response":      {got: tResp(), want: responseKeys},
		"success: zero request":  {got: &Request{}, want: requestKeys},
		"success: zero response": {got: &Response{}, want: responseKeys},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if diff := gocmp.Diff(tt.want, tt.got.GetState().Keys()); diff != "" {
				t.Errorf("key order mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFixtureRoundTrip(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		state func() *state.Map
		load  func(*state.Map) (stateful, error)
	}{
		"success: request": {
			state: fixtureRequestState,
			load:  func(m *state.Map) (stateful, error) { return RequestFromState(m) },
		},
		"success: response": {
			state: fixtureResponseState,
			load:  func(m *state.Map) (stateful, error) { return ResponseFromState(m) },
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			in := tt.state()
			v, err := tt.load(in)
			if err != nil {
				t.Fatalf("FromState: %v", err)
			}
			if in.Len() != 0 {
				t.Errorf("FromState left keys %v", in.Keys())
			}
			if diff := gocmp.Diff(tt.state(), v.GetState()); diff != "" {
				t.Errorf("GetState mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMessageNoneVersusEmpty(t *testing.T) {
	t.Parallel()

	// Ports test_http.py::TestMessage::test_serializable: empty trailers
	// survive a round trip as present-but-empty.
	resp := tResp()
	resp.Trailers = Headers{}
	resp.RawContent = nil
	got, err := ResponseFromState(resp.GetState())
	if err != nil {
		t.Fatal(err)
	}
	if got.Trailers == nil {
		t.Error("empty trailers decoded as None")
	}
	if got.RawContent != nil {
		t.Error("missing content decoded as present")
	}

	m := fixtureRequestState()
	m.Set("content", []byte(nil))
	req, err := RequestFromState(m)
	if err != nil {
		t.Fatal(err)
	}
	if req.RawContent == nil {
		t.Error("empty content bytes decoded as None")
	}
}

func TestSetStateErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate  func(*state.Map)
		wantErr string
	}{
		"error: unexpected fields": {
			mutate:  func(m *state.Map) { m.Set("stream", true) },
			wantErr: "unexpected fields in Request.set_state: [stream]",
		},
		"error: missing field": {
			mutate:  func(m *state.Map) { m.Delete("path") },
			wantErr: `Request.set_state: missing field "path"`,
		},
		"error: str instead of bytes": {
			mutate:  func(m *state.Map) { m.Set("method", "GET") },
			wantErr: `field "method": expected bytes, got str`,
		},
		"error: malformed header pair": {
			mutate:  func(m *state.Map) { m.Set("headers", []any{[]any{[]byte("a")}}) },
			wantErr: `field "headers": header 0: expected a tuple of 2 items, got 1`,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := fixtureRequestState()
			tt.mutate(m)
			r := tReq()
			before := r.GetState()
			err := r.SetState(m)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("SetState error = %v, want it to contain %q", err, tt.wantErr)
			}
			if diff := gocmp.Diff(before, r.GetState()); diff != "" {
				t.Errorf("failed SetState modified the request (-before +after):\n%s", diff)
			}
		})
	}
}

func TestRequestURL(t *testing.T) {
	t.Parallel()

	// Ports test_http.py::TestRequest::test_get_url.
	r := tReq()
	steps := []struct {
		apply       func()
		url, pretty string
	}{
		{func() {}, "http://address:22/path", "http://address:22/path"},
		{func() { r.Scheme = "https" }, "https://address:22/path", "https://address:22/path"},
		{func() { r.SetHost("host"); r.SetPort(42) }, "https://host:42/path", "https://host:42/path"},
		{func() { r.SetHost("address"); r.SetPort(22) }, "https://address:22/path", "https://address:22/path"},
		{func() { r.Headers.Set("Host", "foo.com:22") }, "https://address:22/path", "https://foo.com:22/path"},
	}
	for i, s := range steps {
		s.apply()
		if got := r.URL(); got != s.url {
			t.Errorf("step %d: URL() = %q, want %q", i, got, s.url)
		}
		if got := r.PrettyURL(); got != s.pretty {
			t.Errorf("step %d: PrettyURL() = %q, want %q", i, got, s.pretty)
		}
	}

	// Ports test_http.py::TestRequestUtils::test_url.
	r = tReq()
	if err := r.SetURL("https://otheraddress:42/foo"); err != nil {
		t.Fatal(err)
	}
	if r.Scheme != "https" || r.Host != "otheraddress" || r.Port != 42 || r.Path != "/foo" {
		t.Errorf("SetURL gave scheme=%q host=%q port=%d path=%q", r.Scheme, r.Host, r.Port, r.Path)
	}
	before := r.GetState()
	for _, bad := range []string{"not-a-url", ""} {
		if err := r.SetURL(bad); err == nil {
			t.Errorf("SetURL(%q) succeeded, want an error", bad)
		}
	}
	if diff := gocmp.Diff(before, r.GetState()); diff != "" {
		t.Errorf("failed SetURL modified the request:\n%s", diff)
	}
}

func TestRequestDerived(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		req        func() *Request
		wantURL    string
		wantPretty string
		wantHost   string
		wantFLF    string
	}{
		"success: options asterisk": {
			req: func() *Request {
				r := tReq()
				r.Method, r.Path = "OPTIONS", "*"
				return r
			},
			wantURL: "http://address:22", wantPretty: "http://address:22", wantHost: "address", wantFLF: "relative",
		},
		"success: connect": {
			req: func() *Request {
				r := tReq()
				r.Method, r.Authority = "CONNECT", "example:44"
				return r
			},
			wantURL: "address:22", wantPretty: "example:44", wantHost: "address", wantFLF: "authority",
		},
		"success: host header same port": {
			req: func() *Request {
				r := tReq()
				r.Headers.Set("host", "other:22")
				return r
			},
			wantURL: "http://address:22/path", wantPretty: "http://other:22/path", wantHost: "other", wantFLF: "relative",
		},
		"success: invalid host header is used whole": {
			req: func() *Request {
				r := tReq()
				r.Headers.Set("host", ".disqus.com")
				return r
			},
			wantURL: "http://address:22/path", wantPretty: "http://.disqus.com/path", wantHost: ".disqus.com", wantFLF: "relative",
		},
		"success: absolute form": {
			req: func() *Request {
				r := tReq()
				r.Authority = "example.com"
				return r
			},
			wantURL: "http://address:22/path", wantPretty: "http://address:22/path", wantHost: "address", wantFLF: "absolute",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := tt.req()
			if got := r.URL(); got != tt.wantURL {
				t.Errorf("URL() = %q, want %q", got, tt.wantURL)
			}
			if got := r.PrettyURL(); got != tt.wantPretty {
				t.Errorf("PrettyURL() = %q, want %q", got, tt.wantPretty)
			}
			if got := r.PrettyHost(); got != tt.wantHost {
				t.Errorf("PrettyHost() = %q, want %q", got, tt.wantHost)
			}
			if got := r.FirstLineFormat(); got != tt.wantFLF {
				t.Errorf("FirstLineFormat() = %q, want %q", got, tt.wantFLF)
			}
		})
	}
}

func TestRequestHostHeader(t *testing.T) {
	t.Parallel()

	// Ports test_get_host_header.
	if _, ok := tReq().HostHeader(); ok {
		t.Error("HostHeader present on a request without one")
	}
	h1 := tReq()
	h1.Headers = hdrs("host", "header.example.com")
	h1.Authority = "authority.example.com"
	if got, _ := h1.HostHeader(); got != "header.example.com" {
		t.Errorf("HTTP/1 HostHeader() = %q", got)
	}
	h2 := h1.Clone()
	h2.HTTPVersion = "HTTP/2.0"
	if got, _ := h2.HostHeader(); got != "authority.example.com" {
		t.Errorf("HTTP/2 HostHeader() = %q", got)
	}
	h2.Authority = ""
	if got, _ := h2.HostHeader(); got != "header.example.com" {
		t.Errorf("HTTP/2 HostHeader() without authority = %q", got)
	}

	// Ports test_modify_host_header.
	r := tReq()
	r.SetHostHeader("example.com")
	if r.Headers.Get("Host") != "example.com" || r.Authority != "" {
		t.Errorf("HTTP/1 SetHostHeader: Host=%q authority=%q", r.Headers.Get("Host"), r.Authority)
	}
	r.RemoveHostHeader()
	if r.Headers.Has("host") || r.Authority != "" {
		t.Error("HTTP/1 RemoveHostHeader left data behind")
	}
	r2 := tReq()
	r2.HTTPVersion = "HTTP/2.0"
	r2.SetHostHeader("example.org")
	if r2.Headers.Has("host") || r2.Authority != "example.org" {
		t.Errorf("HTTP/2 SetHostHeader created a Host header or missed authority %q", r2.Authority)
	}
	r2.Headers.Set("Host", "example.org")
	r2.SetHostHeader("foo.example.com")
	if r2.Headers.Get("Host") != "foo.example.com" || r2.Authority != "foo.example.com" {
		t.Errorf("HTTP/2 SetHostHeader: Host=%q authority=%q", r2.Headers.Get("Host"), r2.Authority)
	}
	r2.RemoveHostHeader()
	if r2.Headers.Has("host") || r2.Authority != "" {
		t.Error("HTTP/2 RemoveHostHeader left data behind")
	}

	// Ports test_host_update_also_updates_header.
	r3 := tReq()
	r3.SetHost("example.com")
	if r3.Headers.Has("host") {
		t.Error("SetHost created a Host header")
	}
	r3.Headers.Set("Host", "foo")
	r3.Authority = "foo"
	r3.SetHost("example.org")
	if r3.Headers.Get("Host") != "example.org:22" || r3.Authority != "example.org:22" {
		t.Errorf("SetHost: Host=%q authority=%q, want example.org:22", r3.Headers.Get("Host"), r3.Authority)
	}
}

func TestRequestHelpers(t *testing.T) {
	t.Parallel()

	r := tReq()
	if got := r.String(); got != "Request(GET address:22/path)" {
		t.Errorf("String() = %q", got)
	}
	r.Host = ""
	if got := r.String(); got != "Request(GET /path)" {
		t.Errorf("String() without host = %q", got)
	}

	r = tReq()
	r.Headers.Set("accept-encoding", "gzip, oink")
	r.ConstrainEncoding()
	if got := r.Headers.Get("accept-encoding"); got != "gzip" {
		t.Errorf("ConstrainEncoding() = %q, want gzip", got)
	}
	r.Headers.SetAll("accept-encoding", []string{"gzip", "oink"})
	r.ConstrainEncoding()
	if strings.Contains(r.Headers.Get("accept-encoding"), "oink") {
		t.Error("ConstrainEncoding kept an unknown coding")
	}

	r.Headers.Set("if-modified-since", "x")
	r.Headers.Set("if-none-match", "y")
	r.Anticache()
	if r.Headers.Has("if-modified-since") || r.Headers.Has("if-none-match") {
		t.Error("Anticache left a conditional header")
	}
	r.Anticomp()
	if got := r.Headers.Get("accept-encoding"); got != "identity" {
		t.Errorf("Anticomp() set %q", got)
	}
}

func TestMakeRequest(t *testing.T) {
	t.Parallel()

	r, err := MakeRequest("GET", "https://example.com/", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Method != "GET" || r.Scheme != "https" || r.Host != "example.com" || r.Port != 443 || r.Path != "/" {
		t.Errorf("MakeRequest gave %+v", r)
	}
	r, err = MakeRequest("GET", "https://example.com/", []byte("content"), hdrs("Foo", "bar"))
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := r.Content(); string(c) != "content" || r.Headers.Get("content-length") != "7" || r.Headers.Get("foo") != "bar" {
		t.Errorf("MakeRequest content=%q headers=%q", c, r.Headers.Bytes())
	}
	if _, err := MakeRequest("GET", "not a url", nil, nil); err == nil {
		t.Error("MakeRequest accepted an invalid URL")
	}
}

func TestMakeResponse(t *testing.T) {
	t.Parallel()

	r, err := MakeResponse(200, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := r.Content(); r.StatusCode != 200 || r.Reason != "OK" || c == nil || len(c) != 0 {
		t.Errorf("MakeResponse(200) = %+v", r)
	}
	r, err = MakeResponse(418, []byte("teatime"), hdrs("foo", "bar"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Reason != "I'm a teapot" || r.Headers.Get("content-length") != "7" || r.Headers.Get("foo") != "bar" {
		t.Errorf("MakeResponse(418) = %+v", r)
	}
	if got := StatusText(999); got != "" {
		t.Errorf("StatusText(999) = %q", got)
	}
}

func TestResponseString(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate func(*Response)
		want   string
	}{
		"success: no content type": {mutate: func(*Response) {}, want: "Response(200, unknown content type, 7b)"},
		"success: missing content": {mutate: func(r *Response) { r.RawContent = nil }, want: "Response(200, no content)"},
		"success: content type and kilobytes": {
			mutate: func(r *Response) {
				r.Headers.Set("content-type", "text/html")
				r.RawContent = make([]byte, 2048)
			},
			want: "Response(200, text/html, 2.0k)",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := tResp()
			tt.mutate(r)
			if got := r.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMessageContent(t *testing.T) {
	t.Parallel()

	// Ports test_content_length_update.
	r := tResp()
	r.SetContent([]byte("foo"))
	if string(r.RawContent) != "foo" || r.Headers.Get("content-length") != "3" {
		t.Errorf("after SetContent(foo): raw=%q length=%q", r.RawContent, r.Headers.Get("content-length"))
	}
	r.SetContent([]byte{})
	if r.RawContent == nil || r.Headers.Get("content-length") != "0" {
		t.Errorf("after SetContent(empty): raw=%#v length=%q", r.RawContent, r.Headers.Get("content-length"))
	}
	r.RawContent = []byte("bar")
	if r.Headers.Get("content-length") != "0" {
		t.Error("assigning RawContent changed Content-Length")
	}
	r.SetContent(nil)
	if r.RawContent != nil {
		t.Errorf("SetContent(nil) left raw=%#v", r.RawContent)
	}

	// Ports test_content_length_not_added_for_response_with_transfer_encoding.
	te := tResp()
	te.Headers = hdrs("transfer-encoding", "chunked")
	te.SetContent([]byte("bar"))
	if te.Headers.Has("content-length") {
		t.Error("Content-Length added despite Transfer-Encoding")
	}
}

func TestMessageContentEncoding(t *testing.T) {
	t.Parallel()

	// Ports test_http.py::TestMessageContentEncoding::test_simple and
	// test_update_content_length_header.
	r := tResp()
	if err := r.Encode("gzip"); err != nil {
		t.Fatal(err)
	}
	if r.Headers.Get("content-encoding") != "gzip" || string(r.RawContent) == "message" {
		t.Fatalf("Encode(gzip) left header=%q raw=%q", r.Headers.Get("content-encoding"), r.RawContent)
	}
	if got, want := r.Headers.Get("content-length"), itoa(len(r.RawContent)); got != want {
		t.Errorf("content-length after Encode = %q, want %q", got, want)
	}
	if c, err := r.Content(); err != nil || string(c) != "message" {
		t.Errorf("Content() after gzip = (%q, %v)", c, err)
	}
	r.SetContent([]byte("modified"))
	if c, _ := r.Content(); string(c) != "modified" || string(r.RawContent) == "modified" {
		t.Errorf("SetContent did not re-encode: content=%q raw=%q", c, r.RawContent)
	}
	if err := r.Decode(true); err != nil {
		t.Fatal(err)
	}
	if r.Headers.Has("content-encoding") || string(r.RawContent) != "modified" || r.Headers.Get("content-length") != "8" {
		t.Errorf("Decode left header=%v raw=%q length=%q", r.Headers.Has("content-encoding"), r.RawContent, r.Headers.Get("content-length"))
	}

	// Ports test_unknown_ce: an unknown coding fails strictly and falls
	// back to the raw body leniently.
	u := tResp()
	u.Headers.Set("content-encoding", "zopfli")
	u.RawContent = []byte("foo")
	if _, err := u.Content(); !errors.Is(err, ErrContentEncoding) {
		t.Errorf("Content() with an unknown coding = %v, want ErrContentEncoding", err)
	}
	if got := u.ContentOrRaw(); string(got) != "foo" {
		t.Errorf("ContentOrRaw() = %q", got)
	}

	// Ports test_cannot_decode: a corrupt gzip body.
	bad := tResp()
	bad.Headers.Set("content-encoding", "gzip")
	bad.RawContent = []byte("foo")
	if _, err := bad.Content(); err == nil {
		t.Error("Content() decoded a corrupt gzip body")
	}
	if err := bad.Decode(true); err == nil || !bad.Headers.Has("content-encoding") {
		t.Errorf("strict Decode = %v, header kept = %v", err, bad.Headers.Has("content-encoding"))
	}
	if err := bad.Decode(false); err != nil || bad.Headers.Has("content-encoding") || string(bad.RawContent) != "foo" {
		t.Errorf("lenient Decode = %v, header kept = %v, raw = %q", err, bad.Headers.Has("content-encoding"), bad.RawContent)
	}

	// Ports test_cannot_encode: setting content under an unknown coding
	// drops the header and stores the body as it is.
	ce := tResp()
	ce.Headers.Set("content-encoding", "zopfli")
	ce.SetContent([]byte("foo"))
	if ce.Headers.Has("content-encoding") || string(ce.RawContent) != "foo" {
		t.Errorf("SetContent under unknown coding: header kept = %v, raw = %q", ce.Headers.Has("content-encoding"), ce.RawContent)
	}
	if err := tResp().Encode("zopfli"); !errors.Is(err, ErrContentEncoding) {
		t.Errorf("Encode(zopfli) = %v, want ErrContentEncoding", err)
	}

	// Ports test_decode_noop_on_empty_content.
	empty := tResp()
	empty.Headers.Set("content-encoding", "gzip")
	empty.RawContent = []byte{}
	if err := empty.Decode(true); err != nil || !empty.Headers.Has("content-encoding") {
		t.Errorf("Decode on empty body = %v, header kept = %v", err, empty.Headers.Has("content-encoding"))
	}
}

func TestMessageHTTPVersion(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		version          string
		h10, h11, h2, h3 bool
	}{
		"success: 1.0": {version: "HTTP/1.0", h10: true},
		"success: 1.1": {version: "HTTP/1.1", h11: true},
		"success: 2":   {version: "HTTP/2.0", h2: true},
		"success: 3":   {version: "HTTP/3", h3: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := Message{HTTPVersion: tt.version}
			got := []bool{m.IsHTTP10(), m.IsHTTP11(), m.IsHTTP2(), m.IsHTTP3()}
			if diff := gocmp.Diff([]bool{tt.h10, tt.h11, tt.h2, tt.h3}, got); diff != "" {
				t.Errorf("version predicates mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMessageText(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		contentType string
		content     []byte
		want        string
		wantErr     bool
		wantLenient string
	}{
		"success: latin-1 fallback":      {content: []byte("\xfc"), want: "ü", wantLenient: "ü"},
		"success: latin-1 two bytes":     {content: []byte("\xf0\xe2"), want: "ðâ", wantLenient: "ðâ"},
		"success: charset latin1":        {contentType: "text/html; charset=latin1", content: []byte("\xc3\xbc"), want: "Ã¼", wantLenient: "Ã¼"},
		"success: charset utf8":          {contentType: "text/html; charset=utf8", content: []byte("\xc3\xbc"), want: "ü", wantLenient: "ü"},
		"success: json defaults to utf8": {contentType: "application/json", content: []byte("\"\xc3\xbc\""), want: "\"ü\"", wantLenient: "\"ü\""},
		"success: utf-8 bom is stripped": {content: []byte("\xef\xbb\xbfhi"), want: "hi", wantLenient: "hi"},
		"success: utf-16le bom is kept":  {content: []byte("\xff\xfeh\x00"), want: "\uFEFFh", wantLenient: "\uFEFFh"},
		"error: unknown charset":         {contentType: "text/html; charset=wtf", content: []byte("foo"), wantErr: true, wantLenient: "foo"},
		"error: invalid utf8":            {contentType: "text/html; charset=utf8", content: []byte("\xff"), wantErr: true, wantLenient: "\xff"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := tResp()
			if tt.contentType != "" {
				r.Headers.Set("content-type", tt.contentType)
			}
			r.RawContent = tt.content
			got, err := r.Text()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Text() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Text() = %q, want %q", got, tt.want)
			}
			if got := r.TextOrRaw(); got != tt.wantLenient {
				t.Errorf("TextOrRaw() = %q, want %q", got, tt.wantLenient)
			}
		})
	}
}

func TestMessageSetText(t *testing.T) {
	t.Parallel()

	// Ports test_modify and test_cannot_encode.
	tests := map[string]struct {
		contentType string
		text        string
		wantRaw     string
		wantCT      string
	}{
		"success: latin-1 by default":      {text: "ü", wantRaw: "\xfc"},
		"success: utf8 charset":            {contentType: "text/html; charset=utf8", text: "ü", wantRaw: "\xc3\xbc", wantCT: "text/html; charset=utf8"},
		"success: fallback keeps params":   {contentType: "text/html; charset=latin1; foo=bar", text: "☃", wantRaw: "\xe2\x98\x83", wantCT: "text/html; charset=utf-8; foo=bar"},
		"success: unparsable content type": {contentType: "gibberish", text: "☃", wantRaw: "\xe2\x98\x83", wantCT: "text/plain; charset=utf-8"},
		"success: no content type":         {text: "☃", wantRaw: "\xe2\x98\x83", wantCT: "text/plain; charset=utf-8"},
		"success: raw byte falls back":     {contentType: "text/html; charset=latin1", text: "\xff", wantRaw: "\xff", wantCT: "text/html; charset=utf-8"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := tResp()
			if tt.contentType != "" {
				r.Headers.Set("content-type", tt.contentType)
			}
			r.SetText(tt.text)
			if string(r.RawContent) != tt.wantRaw {
				t.Errorf("raw = %q, want %q", r.RawContent, tt.wantRaw)
			}
			if got := r.Headers.Get("content-type"); got != tt.wantCT {
				t.Errorf("content-type = %q, want %q", got, tt.wantCT)
			}
			if got, want := r.Headers.Get("content-length"), itoa(len(tt.wantRaw)); got != want {
				t.Errorf("content-length = %q, want %q", got, want)
			}
		})
	}
}

func TestInferContentEncoding(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		contentType string
		content     string
		want        string
	}{
		"success: bom utf-32be":             {content: "\x00\x00\xfe\xffx", want: "utf-32be"},
		"success: bom utf-32le over 16le":   {content: "\xff\xfe\x00\x00", want: "utf-32le"},
		"success: bom beats charset":        {contentType: "text/plain; charset=latin1", content: "\xef\xbb\xbf", want: "utf-8-sig"},
		"success: charset":                  {contentType: "text/plain; charset=UTF-8", want: "UTF-8"},
		"success: json":                     {contentType: "application/json", want: "utf8"},
		"success: html meta charset gb2312": {contentType: "text/html", content: `<meta http-equiv="content-type" content="text/html;charset=gb2312">`, want: "gb18030"},
		"success: html default":             {contentType: "text/html", want: "utf8"},
		"success: xml declaration":          {contentType: "application/xml", content: `<?xml version="1.0" encoding="ISO-8859-2"?>`, want: "ISO-8859-2"},
		"success: javascript":               {contentType: "text/javascript", want: "utf8"},
		"success: css charset at start":     {contentType: "text/css", content: `@charset "gb2312";a{}`, want: "gb18030"},
		"success: css charset not at start": {contentType: "text/css", content: `foo@charset "gb2312";`, want: "utf8"},
		"success: charset without css":      {content: `@charset "gb2312";`, want: "latin-1"},
		"success: fallback":                 {contentType: "image/png", want: "latin-1"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := inferContentEncoding(tt.contentType, []byte(tt.content)); got != tt.want {
				t.Errorf("inferContentEncoding(%q, %q) = %q, want %q", tt.contentType, tt.content, got, tt.want)
			}
		})
	}
}

func TestParseContentType(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in     string
		want   contentType
		wantOK bool
	}{
		"success: params": {
			in:     "text/html; charset=UTF-8",
			want:   contentType{Type: "text", Subtype: "html", Params: [][2]string{{"charset", "UTF-8"}}},
			wantOK: true,
		},
		"success: lower-cases media type, skips bare clauses": {
			in:     "Text/HTML; foo; a = b ",
			want:   contentType{Type: "text", Subtype: "html", Params: [][2]string{{"a", "b"}}},
			wantOK: true,
		},
		"error: no slash": {in: "gibberish", wantOK: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseContentType(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("parse mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClone(t *testing.T) {
	t.Parallel()

	r := tReq()
	r.Trailers = hdrs("a", "b")
	c := r.Clone()
	if diff := gocmp.Diff(r.GetState(), c.GetState()); diff != "" {
		t.Fatalf("clone differs:\n%s", diff)
	}
	c.Headers[0].Value[0] = 'X'
	c.RawContent[0] = 'X'
	c.Trailers[0].Name[0] = 'X'
	*c.TimestampEnd = 1
	if r.Headers[0].Value[0] == 'X' || r.RawContent[0] == 'X' || r.Trailers[0].Name[0] == 'X' || *r.TimestampEnd == 1 {
		t.Error("mutating the clone changed the original")
	}
}

func TestRequestSetAuthority(t *testing.T) {
	t.Parallel()

	// Ports test_http.py::TestRequestCore::test_authority for the setter.
	tests := map[string]struct {
		in, want string
	}{
		"success: non-ascii label is punycoded": {in: "ídna.example", want: "xn--dna-qma.example"},
		"success: punycode kept":                {in: "xn--dn-qia9b.example", want: "xn--dn-qia9b.example"},
		"success: transitional mapping":         {in: "fußball", want: "fussball"},
		"success: ascii with port unchanged":    {in: "example.org:22", want: "example.org:22"},
		"success: garbage stored as is":         {in: "foo\xff\x00bar", want: "foo\xff\x00bar"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := tReq()
			r.SetAuthority(tt.in)
			if r.Authority != tt.want {
				t.Errorf("SetAuthority(%q) stored %q, want %q", tt.in, r.Authority, tt.want)
			}
		})
	}
}
