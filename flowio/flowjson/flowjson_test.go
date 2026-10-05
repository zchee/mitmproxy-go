// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowjson_test

import (
	json "encoding/json/v2"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio/flowjson"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/omap"
)

// Upstream test_app.py has no direct flow_to_json tests; TestApp.test_flows
// checks contentHash and errors through the handler. The other handler tests
// exercise Tornado and belong to the web frontend, not this serializer.
func TestFlow(t *testing.T) {
	tests := map[string]struct {
		input flow.Flow
		err   string
	}{
		"error: nil flow":                  {err: "flowjson: nil flow"},
		"error: DNS awaits record helpers": {input: testflow.TDNSFlow(), err: "flowjson: dns flows are not supported yet"},
		"success: HTTP response and error": {input: testflow.TFlow(testflow.WithResponse, testflow.WithError)},
		"success: WebSocket":               {input: testflow.TFlow(testflow.WithResponse, testflow.WithWebSocket)},
		"success: TCP":                     {input: testflow.TTCPFlow()},
		"success: UDP":                     {input: testflow.TUDPFlow()},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := flowjson.Flow(tt.input)
			if tt.err != "" {
				if err == nil || err.Error() != tt.err {
					t.Fatalf("error = %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantKeys := []string{"id", "intercepted", "is_replay", "type", "modified", "marked", "comment", "timestamp_created", "client_conn", "server_conn"}
			if tt.input.Common().Error != nil {
				wantKeys = append(wantKeys, "error")
			}
			if f, ok := tt.input.(*flow.HTTPFlow); ok {
				wantKeys = append(wantKeys, "request")
				if f.Response != nil {
					wantKeys = append(wantKeys, "response")
				}
				if f.WebSocket != nil {
					wantKeys = append(wantKeys, "websocket")
				}
				request, _ := got.Get("request")
				hash, _ := request.(*omap.Map[any]).Get("contentHash")
				if diff := cmp.Diff("ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73", hash); diff != "" {
					t.Errorf("request SHA-256 (-want +got):\n%s", diff)
				}
			} else {
				wantKeys = append(wantKeys, "messages_meta")
			}
			if diff := cmp.Diff(wantKeys, got.Keys()); diff != "" {
				t.Errorf("key order (-want +got):\n%s", diff)
			}
			b, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "raw_content") || strings.Contains(string(b), "\"content\":") {
				t.Errorf("content leaked: %s", b)
			}
		})
	}
}

func TestMissingContentAndTrailers(t *testing.T) {
	f := testflow.TFlow(testflow.WithResponse)
	f.Request.RawContent = nil
	f.Response.RawContent = []byte{}
	f.Response.Trailers.Add("X-Foo", "a")
	f.Response.Trailers.Add("x-foo", "b")
	got, err := flowjson.Flow(f)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := got.Get("request")
	response, _ := got.Get("response")
	for _, key := range []string{"contentHash", "contentLength"} {
		if v, _ := request.(*omap.Map[any]).Get(key); v != nil {
			t.Errorf("missing request %s = %v", key, v)
		}
	}
	hash, _ := response.(*omap.Map[any]).Get("contentHash")
	if diff := cmp.Diff("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash); diff != "" {
		t.Error(diff)
	}
	trailers, _ := response.(*omap.Map[any]).Get("trailers")
	if diff := cmp.Diff([][2]any{{"X-Foo", "a"}, {"x-foo", "b"}}, trailers); diff != "" {
		t.Error(diff)
	}
}
