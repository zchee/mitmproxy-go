// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowjson_test

import (
	"encoding/json/jsontext"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flowio/flowjson"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestDNSFlowJSON(t *testing.T) {
	tests := map[string]struct {
		response bool
		missing  bool
	}{
		"request only":    {},
		"response":        {response: true},
		"missing request": {missing: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := testflow.TDNSFlow(testflow.WithResponse)
			if !tt.response {
				f.Response = nil
			} else {
				f.Response.Timestamp = new(43.0)
			}
			if tt.missing {
				f.Request = nil
			} else {
				f.Request.Timestamp = new(42.0)
			}
			got, err := flowjson.Flow(f)
			if tt.missing {
				if err == nil || err.Error() != "flowjson: DNS flow has no request" || got != nil {
					t.Fatalf("missing DNS request = %v, %v", got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			request, _ := got.Get("request")
			want := f.Request.ToJSON()
			want.Set("timestamp", jsontext.Value("42.0"))
			if diff := gocmp.Diff(want, request); diff != "" {
				t.Fatalf("DNS request JSON (-want +got):\n%s", diff)
			}
			if got.Has("response") != tt.response {
				t.Fatalf("response present = %v, want %v", got.Has("response"), tt.response)
			}
			if tt.response {
				response, _ := got.Get("response")
				want := f.Response.ToJSON()
				want.Set("timestamp", jsontext.Value("43.0"))
				if diff := gocmp.Diff(want, response); diff != "" {
					t.Fatalf("DNS response JSON (-want +got):\n%s", diff)
				}
			}
			if *f.Request.Timestamp != 42 {
				t.Fatal("serialization changed the DNS request")
			}
		})
	}
}
