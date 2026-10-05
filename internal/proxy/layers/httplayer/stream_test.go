// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

type streamAddon struct {
	calls []string
	edit  func(string, *flow.HTTPFlow)
}

func (*streamAddon) Load(ctx context.Context, loader *addon.Loader) error {
	if err := loader.AddOption(ctx, "store_streamed_bodies", options.TypeBool, false,
		"Store HTTP request and response bodies when streamed (see `stream_large_bodies`). "+
			"This increases memory consumption, but makes it possible to inspect streamed bodies."); err != nil {
		return err
	}
	if err := loader.AddOption(ctx, "stream_large_bodies", options.TypeOptStr, (*string)(nil),
		"Stream data to the client if request or response body exceeds the given "+
			"threshold. If streamed, the body will not be stored in any way, "+
			"and such responses cannot be modified. Understands k/m/g "+
			"suffixes, i.e. 3m for 3 megabytes. To store streamed bodies, see `store_streamed_bodies`."); err != nil {
		return err
	}
	return loader.AddOption(ctx, "body_size_limit", options.TypeOptStr, (*string)(nil),
		"Byte size limit of HTTP request and response bodies. Understands "+
			"k/m/g suffixes, i.e. 3m for 3 megabytes.")
}

func (a *streamAddon) record(name string, f *flow.HTTPFlow) error {
	a.calls = append(a.calls, name)
	if a.edit != nil {
		a.edit(name, f)
	}
	return nil
}

func (a *streamAddon) RequestHeaders(_ context.Context, f *flow.HTTPFlow) error {
	return a.record("requestheaders", f)
}

func (a *streamAddon) Request(_ context.Context, f *flow.HTTPFlow) error {
	return a.record("request", f)
}

func (a *streamAddon) ResponseHeaders(_ context.Context, f *flow.HTTPFlow) error {
	return a.record("responseheaders", f)
}

func (a *streamAddon) Response(_ context.Context, f *flow.HTTPFlow) error {
	return a.record("response", f)
}

func (a *streamAddon) Error(_ context.Context, f *flow.HTTPFlow) error {
	return a.record("error", f)
}

func newTestStream(t *testing.T, a *streamAddon, specs ...string) (*httpStream, *master.Master) {
	t.Helper()
	m := master.New(master.Config{})
	t.Cleanup(func() {
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		if err := m.Addons.Add(ctx, a); err != nil {
			return err
		}
		return m.Options.Set(ctx, specs...)
	}); err != nil {
		t.Fatal(err)
	}
	c := &layer.Context{
		Data: &hookdata.Context{
			Client: connection.NewClient(connection.Address{}, connection.Address{}, 1),
			Server: connection.NewServer(nil), Options: m.Options,
		},
		Hooks: &proxy.HookRunner{Manager: m.Addons}, Do: m.Do,
	}
	return &httpStream{c: c, id: 1}, m
}

func requestHead(length string) RequestHeaders {
	return RequestHeaders{ID: 1, Request: &httpmsg.Request{
		HTTPVersion: "HTTP/1.1", Method: "POST", Scheme: "http", Host: "example.com", Port: 80, Path: "/",
		Headers: httpmsg.Headers{{Name: []byte("Content-Length"), Value: []byte(length)}},
	}}
}

func responseHead(length string) ResponseHeaders {
	return ResponseHeaders{ID: 1, Response: &httpmsg.Response{
		HTTPVersion: "HTTP/1.1", StatusCode: 200, Reason: "OK",
		Headers: httpmsg.Headers{{Name: []byte("Content-Length"), Value: []byte(length)}},
	}}
}

func drainStream(t *testing.T, s *httpStream, event Event) []Event {
	t.Helper()
	out, err := s.handle(t.Context(), event)
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	for {
		events = append(events, out.events...)
		if out.after == nil {
			return events
		}
		out, err = out.after(t.Context())
		if err != nil {
			t.Fatal(err)
		}
	}
}

func bodyEvents(events []Event) []byte {
	var body []byte
	for _, event := range events {
		switch event := event.(type) {
		case RequestData:
			body = append(body, event.Data...)
		case ResponseData:
			body = append(body, event.Data...)
		}
	}
	return body
}

func TestStreamBufferedRoundTrip(t *testing.T) {
	a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
		switch name {
		case "request":
			f.Request.RawContent = bytes.ToUpper(f.Request.RawContent)
			f.Request.Trailers.Set("Request-End", "changed")
		case "response":
			f.Response.RawContent = bytes.ToUpper(f.Response.RawContent)
		}
	}}
	s, _ := newTestStream(t, a)
	for _, event := range []Event{requestHead("3"), RequestData{ID: 1, Data: []byte("abc")}, RequestTrailers{ID: 1, Trailers: httpmsg.Headers{{Name: []byte("Request-End"), Value: []byte("original")}}}} {
		if events := drainStream(t, s, event); len(events) != 0 {
			t.Fatalf("buffered request sent early: %v", events)
		}
	}
	request := drainStream(t, s, RequestEndOfMessage{ID: 1})
	if diff := gocmp.Diff("ABC", string(bodyEvents(request))); diff != "" {
		t.Fatal(diff)
	}
	if got := request[2].(RequestTrailers).Trailers.Get("Request-End"); got != "changed" {
		t.Fatalf("request trailer = %q", got)
	}
	for _, event := range []Event{responseHead("3"), ResponseData{ID: 1, Data: []byte("def")}} {
		if events := drainStream(t, s, event); len(events) != 0 {
			t.Fatalf("buffered response sent early: %v", events)
		}
	}
	response := drainStream(t, s, ResponseEndOfMessage{ID: 1})
	if diff := gocmp.Diff("DEF", string(bodyEvents(response))); diff != "" {
		t.Fatal(diff)
	}
	if diff := gocmp.Diff([]string{"requestheaders", "request", "responseheaders", "response"}, a.calls); diff != "" {
		t.Fatal(diff)
	}
	if !s.done() || s.snapshot.Live || s.snapshot.Request.TimestampEnd == nil || s.snapshot.Response.TimestampEnd == nil {
		t.Fatalf("incomplete flow: done=%v snapshot=%+v", s.done(), s.snapshot)
	}
}

func TestStreamTransforms(t *testing.T) {
	tests := map[string]struct{ store bool }{
		"success: discard streamed bodies":   {},
		"success: retain transformed bodies": {store: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var chunks []string
			a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				transform := func(chunk []byte) [][]byte {
					chunks = append(chunks, string(chunk))
					return [][]byte{nil, []byte("["), bytes.Clone(chunk), []byte("]")}
				}
				switch name {
				case "requestheaders":
					f.Request.StreamFunc = transform
				case "responseheaders":
					f.Response.StreamFunc = transform
				}
			}}
			s, _ := newTestStream(t, a, fmt.Sprintf("store_streamed_bodies=%v", tt.store))
			request := drainStream(t, s, requestHead("3"))
			request = append(request, drainStream(t, s, RequestData{ID: 1, Data: []byte("abc")})...)
			out, err := s.handle(t.Context(), RequestEndOfMessage{ID: 1})
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff([]string{"requestheaders"}, a.calls); diff != "" {
				t.Fatalf("request hook ran before final transform bytes were sent: %s", diff)
			}
			request = append(request, out.events...)
			if out.after == nil {
				t.Fatal("missing post-flush continuation")
			}
			out, err = out.after(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			request = append(request, out.events...)
			response := drainStream(t, s, responseHead("3"))
			response = append(response, drainStream(t, s, ResponseData{ID: 1, Data: []byte("def")})...)
			response = append(response, drainStream(t, s, ResponseEndOfMessage{ID: 1})...)
			if diff := gocmp.Diff([]string{"abc", "", "def", ""}, chunks); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff("[abc][]", string(bodyEvents(request))); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff("[def][]", string(bodyEvents(response))); diff != "" {
				t.Fatal(diff)
			}
			var wantRequest, wantResponse []byte
			if tt.store {
				wantRequest, wantResponse = []byte("[abc][]"), []byte("[def][]")
			}
			if diff := gocmp.Diff(wantRequest, s.snapshot.Request.RawContent); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff(wantResponse, s.snapshot.Response.RawContent); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestStreamThresholdAndLimits(t *testing.T) {
	tests := map[string]struct {
		option string
		known  bool
		code   ErrorCode
	}{
		"success: declared streaming threshold":    {"stream_large_bodies=1k", true, 0},
		"success: accumulated streaming threshold": {"stream_large_bodies=1k", false, 0},
		"error: declared request limit":            {"body_size_limit=1k", true, RequestTooLarge},
		"error: accumulated request limit":         {"body_size_limit=1k", false, RequestTooLarge},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := &streamAddon{}
			s, _ := newTestStream(t, a, tt.option)
			head := requestHead("2048")
			if !tt.known {
				head.Request.Headers = httpmsg.Headers{{Name: []byte("Transfer-Encoding"), Value: []byte("chunked")}}
			}
			events := drainStream(t, s, head)
			if !tt.known || tt.code == 0 {
				events = append(events, drainStream(t, s, RequestData{ID: 1, Data: bytes.Repeat([]byte("x"), 2048)})...)
			}
			if tt.code != 0 {
				failure := events[0].(ResponseProtocolError)
				if diff := gocmp.Diff(ResponseProtocolError{ID: 1, Code: tt.code, Message: "Request body exceeds mitmproxy's body_size_limit."}, failure); diff != "" {
					t.Fatal(diff)
				}
				if diff := gocmp.Diff([]string{"requestheaders", "error"}, a.calls); diff != "" {
					t.Fatal(diff)
				}
				if !s.done() || s.snapshot.Live {
					t.Fatal("oversized flow remains live")
				}
				return
			}
			if len(bodyEvents(events)) != 2048 || !s.snapshot.Request.Stream {
				t.Fatal("threshold did not start streaming the accumulated body")
			}
			drainStream(t, s, RequestEndOfMessage{ID: 1})
			if s.snapshot.Request.RawContent != nil {
				t.Fatal("streaming retained body without store_streamed_bodies")
			}
		})
	}
}

func TestStreamSyntheticResponseAndInformational(t *testing.T) {
	tests := map[string]struct{ synthetic bool }{
		"success: addon response":         {true},
		"success: informational response": {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				if tt.synthetic && name == "request" {
					f.Response = &httpmsg.Response{HTTPVersion: "HTTP/1.1", StatusCode: 418, RawContent: []byte("teapot")}
				}
			}}
			s, _ := newTestStream(t, a)
			head := requestHead("0")
			head.EndStream = true
			drainStream(t, s, head)
			events := drainStream(t, s, RequestEndOfMessage{ID: 1})
			if tt.synthetic {
				if diff := gocmp.Diff("teapot", string(bodyEvents(events))); diff != "" {
					t.Fatal(diff)
				}
			} else {
				info := ResponseHeaders{ID: 1, Response: &httpmsg.Response{HTTPVersion: "HTTP/1.1", StatusCode: 103}, EndStream: true}
				if got := drainStream(t, s, info); len(got) != 1 || got[0].(ResponseHeaders).Response.StatusCode != 103 {
					t.Fatalf("informational output: %v", got)
				}
				drainStream(t, s, responseHead("0"))
				drainStream(t, s, ResponseEndOfMessage{ID: 1})
			}
			if diff := gocmp.Diff([]string{"requestheaders", "request", "responseheaders", "response"}, a.calls); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestStreamTransformHoldsDispatchLock(t *testing.T) {
	var held atomic.Bool
	m := master.New(master.Config{
		OnDispatchStart: func() { held.Store(true) },
		OnDispatchEnd:   func() { held.Store(false) },
	})
	t.Cleanup(func() { _ = m.Close(context.WithoutCancel(t.Context())) })
	started, finished := make(chan struct{}), make(chan struct{})
	var calls int
	a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
		if name != "requestheaders" {
			return
		}
		f.Request.StreamFunc = func(chunk []byte) [][]byte {
			if !held.Load() {
				t.Error("StreamFunc ran outside dispatch lock")
			}
			if calls == 0 {
				go func() {
					close(started)
					if err := m.Do(t.Context(), func(context.Context) error { return nil }); err != nil {
						t.Error(err)
					}
					close(finished)
				}()
				<-started
				select {
				case <-finished:
					t.Error("competing Do completed during StreamFunc")
				default:
				}
			}
			calls++
			return [][]byte{bytes.Clone(chunk)}
		}
	}}
	if err := m.Addons.Add(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	s := &httpStream{id: 1, c: &layer.Context{
		Data:  &hookdata.Context{Client: connection.NewClient(connection.Address{}, connection.Address{}, 1), Server: connection.NewServer(nil), Options: m.Options},
		Hooks: &proxy.HookRunner{Manager: m.Addons}, Do: m.Do,
	}}
	drainStream(t, s, requestHead("3"))
	drainStream(t, s, RequestData{ID: 1, Data: []byte("abc")})
	<-finished
	drainStream(t, s, RequestEndOfMessage{ID: 1})
	if calls != 2 {
		t.Fatalf("transform calls = %d, want data plus final empty", calls)
	}
}

func TestStreamExpectContinue(t *testing.T) {
	a := &streamAddon{}
	s, _ := newTestStream(t, a)
	head := requestHead("3")
	head.Request.Headers.Set("Expect", "100-continue")
	events := drainStream(t, s, head)
	if len(events) != 1 {
		t.Fatalf("continue output = %v, want one informational head", events)
	}
	response := events[0].(ResponseHeaders).Response
	if response.StatusCode != 100 || response.Reason != "Continue" || len(response.Headers) != 0 {
		t.Fatalf("continue response = %+v", response)
	}
	drainStream(t, s, RequestData{ID: 1, Data: []byte("abc")})
	events = drainStream(t, s, RequestEndOfMessage{ID: 1})
	if _, found := events[0].(RequestHeaders).Request.Headers.Lookup("Expect"); found {
		t.Fatal("Expect was forwarded after the proxy acknowledged it")
	}
}

func TestStreamResponseLimit(t *testing.T) {
	tests := map[string]struct{ known bool }{
		"error: declared response limit":    {true},
		"error: accumulated response limit": {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := &streamAddon{}
			s, _ := newTestStream(t, a, "body_size_limit=1k")
			drainStream(t, s, requestHead("0"))
			drainStream(t, s, RequestEndOfMessage{ID: 1})
			head := responseHead("2048")
			if !tt.known {
				head.Response.Headers = nil
			}
			events := drainStream(t, s, head)
			if !tt.known {
				events = append(events, drainStream(t, s, ResponseData{ID: 1, Data: bytes.Repeat([]byte("x"), 2048)})...)
			}
			want := []Event{
				ResponseProtocolError{ID: 1, Code: ResponseTooLarge, Message: "Response body exceeds mitmproxy's body_size_limit."},
				RequestProtocolError{ID: 1, Code: ResponseTooLarge, Message: "Response body exceeds mitmproxy's body_size_limit."},
			}
			if diff := gocmp.Diff(want, events); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff([]string{"requestheaders", "request", "responseheaders", "error"}, a.calls); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestStreamKilledHooks(t *testing.T) {
	tests := map[string]struct{ want []string }{
		"requestheaders":  {[]string{"requestheaders", "error"}},
		"request":         {[]string{"requestheaders", "request", "error"}},
		"responseheaders": {[]string{"requestheaders", "request", "responseheaders", "error"}},
		"response":        {[]string{"requestheaders", "request", "responseheaders", "response"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := &streamAddon{edit: func(hook string, f *flow.HTTPFlow) {
				if hook == name {
					if err := f.Kill(); err != nil {
						t.Error(err)
					}
				}
			}}
			s, _ := newTestStream(t, a)
			var failures []Event
			for _, event := range []Event{requestHead("0"), RequestEndOfMessage{ID: 1}, responseHead("0"), ResponseEndOfMessage{ID: 1}} {
				for _, emitted := range drainStream(t, s, event) {
					if failure, ok := emitted.(ResponseProtocolError); ok {
						failures = append(failures, failure)
					}
				}
			}
			if len(failures) != 1 || failures[0].(ResponseProtocolError).Code != Kill {
				t.Fatalf("kill output = %v", failures)
			}
			if diff := gocmp.Diff(tt.want, a.calls); diff != "" {
				t.Fatal(diff)
			}
			if !s.done() || s.snapshot.Live {
				t.Fatal("killed flow remains live")
			}
		})
	}
}

func TestStreamEarlyResponseAndPendingFlush(t *testing.T) {
	tests := map[string]struct{ terminate bool }{
		"success: upload continues after early response": {},
		"error: discard continuation after termination":  {true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				if name == "requestheaders" {
					f.Request.StreamFunc = func(b []byte) [][]byte { return [][]byte{bytes.Clone(b)} }
				}
			}}
			s, _ := newTestStream(t, a)
			drainStream(t, s, requestHead("3"))
			drainStream(t, s, RequestData{ID: 1, Data: []byte("abc")})
			pending, err := s.handle(t.Context(), RequestEndOfMessage{ID: 1})
			if err != nil {
				t.Fatal(err)
			}
			if tt.terminate {
				drainStream(t, s, ResponseProtocolError{ID: 1, Code: GenericServerError, Message: "server closed connection"})
			} else {
				head := responseHead("0")
				head.Response.StatusCode, head.Response.Reason = 413, "Request Entity Too Large"
				drainStream(t, s, head)
				drainStream(t, s, ResponseEndOfMessage{ID: 1})
				if s.done() {
					t.Fatal("early response ended an unfinished upload")
				}
			}
			out, err := pending.after(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if tt.terminate {
				if len(out.events) != 0 || out.after != nil {
					t.Fatalf("terminated stream resumed its flush: %+v", out)
				}
				if diff := gocmp.Diff([]string{"requestheaders", "error"}, a.calls); diff != "" {
					t.Fatal(diff)
				}
			} else if diff := gocmp.Diff([]string{"requestheaders", "responseheaders", "response", "request"}, a.calls); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

var _ addon.RequestHandler = (*streamAddon)(nil)
