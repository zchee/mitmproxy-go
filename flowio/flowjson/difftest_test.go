// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package flowjson_test

import (
	"bytes"
	json "encoding/json/v2"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/flowio/flowjson"
	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestDifferentialFlow(t *testing.T) {
	tests := map[string]struct{ input flow.Flow }{
		"success: HTTP response error and certificate": {testflow.TFlow(testflow.WithResponse, testflow.WithError)},
		"success: missing content and WebSocket":       {testflow.TFlow(testflow.WithResponse, testflow.WithWebSocket)},
		"success: binary header and path":              {testflow.TFlow()},
		"success: multibyte reason bytes":              {testflow.TFlow(testflow.WithResponse)},
		"success: mixed reason bytes":                  {testflow.TFlow(testflow.WithResponse)},
		"success: TCP":                                 {testflow.TTCPFlow()},
		"success: UDP":                                 {testflow.TUDPFlow()},
		"success: empty TCP":                           {flow.NewTCPFlow(testflow.TClientConn(), testflow.TServerConn(), false)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := tt.input
			f.Common().Marked = ":grapes:"
			if h, ok := f.(*flow.HTTPFlow); ok && h.WebSocket != nil {
				h.Request.RawContent = nil
				h.Response.RawContent = nil
			}
			if name == "success: binary header and path" {
				h := f.(*flow.HTTPFlow)
				h.Request.Headers.Add("X-Binary", string([]byte{255, 254}))
				h.Request.Method = "g" + string([]byte{255, 254}) + "et"
				h.Request.Path = "/" + string([]byte{255, 254})
			}
			if name == "success: multibyte reason bytes" {
				f.(*flow.HTTPFlow).Response.Reason = string([]byte{0xc3, 0xa9})
			}
			if name == "success: mixed reason bytes" {
				f.(*flow.HTTPFlow).Response.Reason = "OK " + string([]byte{0xc3, 0xa9}) + "!"
			}
			var state bytes.Buffer
			if err := flowio.NewWriter(&state).Add(f); err != nil {
				t.Fatal(err)
			}
			want := difftest.Python(t, `import io,json,sys
from mitmproxy.io import FlowReader
from mitmproxy.tools.web.app import flow_to_json
f = next(FlowReader(io.BytesIO(sys.stdin.buffer.read())).stream())
sys.stdout.buffer.write(json.dumps(flow_to_json(f), ensure_ascii=False, separators=(",", ":")).encode("utf8", "backslashreplace"))
`, state.Bytes())
			obj, err := flowjson.Flow(f)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.Marshal(obj)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(string(want), string(got)); diff != "" {
				t.Errorf("flow JSON (-Python +Go):\n%s", diff)
			}
		})
	}
}
