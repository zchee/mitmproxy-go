// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Upstream test/mitmproxy/addons/test_dumper.py maps onto this file as
// follows:
//
//	test_configure           -> TestConfigure
//	test_simple              -> TestSimple
//	test_echo_body           -> TestEchoBody/default cutoff
//	test_echo_body_custom_cutoff -> TestEchoBody/custom cutoff
//	test_echo_trailer        -> TestEchoTrailer
//	test_echo_request_line   -> TestEchoRequestLine
//	test_tcp                 -> TestProtocols/tcp message, tcp error
//	test_udp                 -> TestProtocols/udp message, udp error
//	test_dns                 -> TestProtocols/dns answer, dns no answer,
//	                            dns error; TestDNSRecordData
//	test_websocket           -> TestProtocols/websocket *
//	test_http_connect_error  -> TestProtocols/connect error
//	test_http2               -> TestSimple/http2
//	test_quic                -> TestProtocols/quic stream, quic datagram
//	test_styling             -> TestStyling
//	test_has_styles_for_tags -> not applicable: it checks the Python
//	                            highlighter's tag list against
//	                            CONTENTVIEW_STYLES; message content is
//	                            deliberately uncoloured until the syntax
//	                            highlighter is ported (docs/compat.md).
package dumper

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func setup(t *testing.T) (*Dumper, *addon.Manager, *bytes.Buffer) {
	t.Helper()
	opts := options.New()
	output := new(bytes.Buffer)
	d := New(opts, output)
	m := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(m.Close)
	if err := m.Add(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	return d, m, output
}

func configure(t *testing.T, m *addon.Manager, values map[string]any) error {
	t.Helper()
	return m.Do(t.Context(), func(ctx context.Context) error { return m.Options().Update(ctx, values) })
}

func TestConfigure(t *testing.T) {
	d, m, _ := setup(t)
	if err := configure(t, m, map[string]any{"dumper_filter": new("~b foo")}); err != nil {
		t.Fatal(err)
	}
	f := testflow.TFlow(testflow.WithResponse)
	if d.match(f) {
		t.Fatal("unexpected match")
	}
	f.Response.SetContent([]byte("foo"))
	if !d.match(f) {
		t.Fatal("body filter did not match")
	}
	if err := configure(t, m, map[string]any{"dumper_filter": nil}); err != nil {
		t.Fatal(err)
	}
	if err := configure(t, m, map[string]any{"dumper_filter": new("~~")}); err == nil {
		t.Fatal("invalid filter accepted")
	}
	if d.filter != nil {
		t.Fatal("failed update changed the filter")
	}
}

// TestSimple ports test_simple and test_http2, including missing content,
// replay, invalid JSON, errors, and response-version display.
func TestSimple(t *testing.T) {
	tests := map[string]struct {
		detail int
		edit   func(*flow.HTTPFlow)
		want   string
		quiet  bool
	}{
		"quiet":           {detail: 0, quiet: true},
		"summary":         {detail: 1, want: "200 OK"},
		"verbose":         {detail: 4, want: " << 200 OK"},
		"error":           {detail: 4, edit: func(f *flow.HTTPFlow) { f.Error = testflow.TErr() }, want: " << error"},
		"replay redirect": {detail: 4, edit: func(f *flow.HTTPFlow) { f.IsReplay = new("response"); f.Response.StatusCode = 300 }, want: "[replay] << 300"},
		"invalid json": {detail: 4, edit: func(f *flow.HTTPFlow) {
			f.Response.SetContent([]byte("{"))
			f.Response.Headers.Set("content-type", "application/json")
			f.Response.StatusCode = 400
		}, want: "    {"},
		"missing content": {detail: 4, edit: func(f *flow.HTTPFlow) { f.Request.RawContent = nil; f.Response.RawContent = nil }, want: "(content missing)"},
		"http2":           {detail: 1, edit: func(f *flow.HTTPFlow) { f.Response.HTTPVersion = "HTTP/2.0"; f.Response.Reason = "ignored" }, want: "HTTP/2.0 200 OK"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d, m, out := setup(t)
			if err := configure(t, m, map[string]any{"flow_detail": tt.detail}); err != nil {
				t.Fatal(err)
			}
			f := testflow.TFlow(testflow.WithResponse)
			if tt.edit != nil {
				tt.edit(f)
			}
			if err := d.Response(t.Context(), f); err != nil {
				t.Fatal(err)
			}
			if tt.quiet && out.Len() != 0 {
				t.Fatal(out.String())
			}
			if !tt.quiet && !strings.Contains(out.String(), tt.want) {
				t.Fatalf("want %q in %q", tt.want, out.String())
			}
			if strings.Contains(out.String(), "\x1b[") {
				t.Fatal("pipe output contains ANSI codes")
			}
		})
	}
}

// TestEchoBody ports test_echo_body and test_echo_body_custom_cutoff.
func TestEchoBody(t *testing.T) {
	tests := map[string]struct {
		lines, cutoff, detail int
		cut                   bool
	}{
		"default cutoff": {600, 512, 3, true},
		"custom cutoff":  {4, 3, 3, true},
		"full":           {600, 3, 4, false},
		"exact cutoff":   {3, 3, 3, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d, m, out := setup(t)
			if err := configure(t, m, map[string]any{"flow_detail": tt.detail, "content_view_lines_cutoff": tt.cutoff}); err != nil {
				t.Fatal(err)
			}
			f := testflow.TFlow(testflow.WithResponse)
			f.Response.Headers.Set("content-type", "text/html")
			f.Response.SetContent([]byte(strings.Repeat("foo bar voing\n", tt.lines)))
			if err := d.echoMessage(f.Response, f); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(out.String(), "(cut off)"); got != tt.cut {
				t.Fatalf("cut=%v, want %v: %q", got, tt.cut, out.String())
			}
			// The pinned dumper tests the cut text but prints the uncut highlighted
			// text. Keep that observable behavior rather than silently correcting it.
			if got := strings.Count(out.String(), "foo bar voing"); got != tt.lines {
				t.Fatalf("printed %d lines, want %d", got, tt.lines)
			}
		})
	}
}

func TestEchoTrailer(t *testing.T) {
	d, m, out := setup(t)
	if err := configure(t, m, map[string]any{"flow_detail": 3, "content_view_lines_cutoff": 3}); err != nil {
		t.Fatal(err)
	}
	f := testflow.TFlow(testflow.WithResponse)
	for _, msg := range []*httpmsg.Message{&f.Request.Message, &f.Response.Message} {
		msg.Headers.Set("content-type", "text/html")
		msg.Headers.Set("transfer-encoding", "chunked")
		msg.Headers.Set("trailer", "my-little-trailer")
		msg.SetContent([]byte(strings.Repeat("some content\n", 10)))
		msg.Trailers = httpmsg.Headers{{Name: []byte("my-little-trailer"), Value: []byte("foobar-trailer")}}
	}
	if err := d.Response(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"content-type", "cut off", "some content", "--- HTTP Trailers", "foobar-trailer"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in %q", want, out.String())
		}
	}
}

func TestEchoRequestLine(t *testing.T) {
	t.Setenv("COLUMNS", "80")
	tests := map[string]struct {
		detail       int
		edit         func(*flow.HTTPFlow)
		want, absent string
	}{
		"replay":    {3, func(f *flow.HTTPFlow) { f.IsReplay = new("request") }, "[replay]", ""},
		"normal":    {3, func(f *flow.HTTPFlow) { f.IsReplay = nil }, "GET", "[replay]"},
		"version":   {3, func(f *flow.HTTPFlow) { f.Request.HTTPVersion = "nonstandard" }, "nonstandard", ""},
		"truncated": {1, func(f *flow.HTTPFlow) { f.Request.Path = "/" + strings.Repeat("x", 80) + "textToBeTruncated" }, "…", "textToBeTruncated"},
		"pushed":    {3, func(f *flow.HTTPFlow) { f.Metadata.Set("h2-pushed-stream", true) }, "PUSH_PROMISE", ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d, m, out := setup(t)
			if err := configure(t, m, map[string]any{"flow_detail": tt.detail, "showhost": true}); err != nil {
				t.Fatal(err)
			}
			f := testflow.TFlow(testflow.WithResponse)
			tt.edit(f)
			if err := d.echoRequestLine(f); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), tt.want) || tt.absent != "" && strings.Contains(out.String(), tt.absent) {
				t.Fatalf("got %q, want %q, absent %q", out.String(), tt.want, tt.absent)
			}
		})
	}
}

// TestWidthFrom checks the URL-wrapping width against Python's
// shutil.get_terminal_size order: positive COLUMNS, terminal width, 80.
func TestWidthFrom(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()

	tests := map[string]struct {
		env    string
		stdout *os.File
		want   int
	}{
		"success: positive COLUMNS wins":           {env: "120", stdout: w, want: 120},
		"success: no COLUMNS, no terminal is 80":   {env: "", stdout: w, want: 80},
		"error: zero COLUMNS falls through":        {env: "0", stdout: w, want: 80},
		"error: negative COLUMNS falls through":    {env: "-3", stdout: w, want: 80},
		"error: non-numeric COLUMNS falls through": {env: "wide", stdout: w, want: 80},
		"error: nil stdout is 80":                  {env: "", stdout: nil, want: 80},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := widthFrom(tt.env, tt.stdout); got != tt.want {
				t.Fatalf("widthFrom(%q) = %d, want %d", tt.env, got, tt.want)
			}
		})
	}
}

// TestProtocols ports test_tcp, test_udp, test_dns, test_websocket,
// test_http_connect_error, and test_quic through the real hook dispatcher.
func TestProtocols(t *testing.T) {
	tests := map[string]struct {
		hook func() addon.Hook
		want string
	}{
		"tcp message": {func() addon.Hook { return addon.TCPMessageHook{Flow: testflow.TTCPFlow()} }, "it's me"},
		"tcp error":   {func() addon.Hook { return addon.TCPErrorHook{Flow: testflow.TTCPFlow(testflow.WithError)} }, "Error in TCP"},
		"udp message": {func() addon.Hook { return addon.UDPMessageHook{Flow: testflow.TUDPFlow()} }, "it's me"},
		"udp error":   {func() addon.Hook { return addon.UDPErrorHook{Flow: testflow.TUDPFlow(testflow.WithError)} }, "Error in UDP"},
		"dns answer":  {func() addon.Hook { return addon.DNSResponseHook{Flow: testflow.TDNSFlow(testflow.WithResponse)} }, "8.8.8.8"},
		"dns no answer": {func() addon.Hook {
			f := testflow.TDNSFlow(testflow.WithResponse)
			f.Response.Answers = nil
			f.Response.ResponseCode = dns.ResponseCodeNOTIMP
			return addon.DNSResponseHook{Flow: f}
		}, "NOTIMP"},
		"dns error":         {func() addon.Hook { return addon.DNSErrorHook{Flow: testflow.TDNSFlow(testflow.WithError)} }, "error"},
		"websocket message": {func() addon.Hook { return addon.WebSocketMessageHook{Flow: testflow.TWebSocketFlow()} }, "it's me"},
		"websocket end":     {func() addon.Hook { return addon.WebSocketEndHook{Flow: testflow.TWebSocketFlow()} }, "WebSocket connection closed by"},
		"websocket error":   {func() addon.Hook { return addon.WebSocketEndHook{Flow: testflow.TWebSocketFlow(testflow.WithError)} }, "Error in WebSocket"},
		"websocket error reason": {func() addon.Hook {
			f := testflow.TWebSocketFlow(testflow.WithError)
			f.WebSocket.CloseReason = new("Some lame excuse")
			return addon.WebSocketEndHook{Flow: f}
		}, "(reason: Some lame excuse)"},
		"websocket unknown": {func() addon.Hook {
			f := testflow.TWebSocketFlow()
			f.WebSocket.CloseCode = new(4000)
			return addon.WebSocketEndHook{Flow: f}
		}, "UNKNOWN_ERROR=4000"},
		"websocket unknown reason": {func() addon.Hook {
			f := testflow.TWebSocketFlow()
			f.WebSocket.CloseCode = new(4000)
			f.WebSocket.CloseReason = new("I swear I had a reason")
			return addon.WebSocketEndHook{Flow: f}
		}, "(reason: I swear I had a reason)"},
		"connect error": {func() addon.Hook {
			f := testflow.TFlow(testflow.WithResponse)
			f.Response.StatusCode = 502
			f.Response.Reason = "Bad Gateway"
			return addon.HTTPConnectErrorHook{Flow: f}
		}, "502 Bad Gateway"},
		"http error": {func() addon.Hook { return addon.ErrorHook{Flow: testflow.TFlow(testflow.WithError)} }, "error"},
		"quic stream": {func() addon.Hook {
			f := testflow.TTCPFlow()
			f.ClientConn.TLSVersion = "QUICv1"
			f.Metadata.Set("quic_stream_id_client", 1)
			f.Metadata.Set("quic_stream_id_server", 1)
			return addon.TCPMessageHook{Flow: f}
		}, "quic stream 1"},
		"quic datagram": {func() addon.Hook {
			f := testflow.TUDPFlow()
			f.ClientConn.TLSVersion = "QUICv1"
			f.Metadata.Set("quic_stream_id_client", 1)
			f.Metadata.Set("quic_stream_id_server", 1)
			return addon.UDPMessageHook{Flow: f}
		}, "quic dgrams 1"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, m, out := setup(t)
			if err := configure(t, m, map[string]any{"flow_detail": 3}); err != nil {
				t.Fatal(err)
			}
			if err := m.Hook(t.Context(), tt.hook()); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), tt.want) {
				t.Fatalf("want %q in %q", tt.want, out.String())
			}
			out.Reset()
			if err := configure(t, m, map[string]any{"flow_detail": 0}); err != nil {
				t.Fatal(err)
			}
			if err := m.Hook(t.Context(), tt.hook()); err != nil {
				t.Fatal(err)
			}
			if out.Len() != 0 {
				t.Fatalf("quiet printed %q", out.String())
			}
		})
	}
}

func TestStyling(t *testing.T) {
	d, _, out := setup(t)
	d.outHasVT = true
	if err := d.Response(t.Context(), testflow.TFlow(testflow.WithResponse)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "\x1b[") {
		t.Fatal("terminal has no style")
	}
}

// Upstream test_has_styles_for_tags concerns the syntax-highlighting registry,
// not flow rendering. Message content is deliberately uncoloured until the
// highlighter is ported; terminal request, status and header styles are tested.

func TestWriteFailure(t *testing.T) {
	d, _, _ := setup(t)
	reader, writer := io.Pipe()
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	d.out = writer
	if err := d.Response(t.Context(), testflow.TFlow(testflow.WithResponse)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("got %v, want closed pipe", err)
	}
}

func TestConcurrentDispatch(t *testing.T) {
	_, m, out := setup(t)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if err := m.Hook(t.Context(), addon.ResponseHook{Flow: testflow.TFlow(testflow.WithResponse)}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if got := strings.Count(out.String(), "200 OK"); got != 20 {
		t.Fatalf("got %d responses", got)
	}
}

func TestOptions(t *testing.T) {
	d, m, _ := setup(t)
	_ = d
	tests := map[string]struct {
		typ options.Type
		def any
	}{
		"flow_detail":                {options.TypeInt, 1},
		"dumper_default_contentview": {options.TypeStr, "auto"},
		"dumper_filter":              {options.TypeOptStr, (*string)(nil)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			o, ok := m.Options().Lookup(name)
			if !ok {
				t.Fatal("option not registered")
			}
			if diff := gocmp.Diff(tt.typ, o.Type()); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff(tt.def, o.Default()); diff != "" {
				t.Fatal(diff)
			}
			for line := range strings.SplitSeq(string(testutil.Fixture(t, "options-upstream.txt")), "\n") {
				if strings.HasPrefix(line, name+"\t") {
					fields := strings.Split(line, "\t")
					if diff := gocmp.Diff(fields[3], o.Help()); diff != "" {
						t.Fatal(diff)
					}
				}
			}
		})
	}
	o, _ := m.Options().Lookup("dumper_default_contentview")
	if diff := gocmp.Diff(contentviews.DefaultRegistry.AvailableViews(), o.Choices()); diff != "" {
		t.Fatal(diff)
	}
}
