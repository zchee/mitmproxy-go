// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package har_test

import (
	"bytes"
	"encoding/base64"
	json "encoding/json/v2"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/flowio/flowjson"
	"github.com/zchee/mitmproxy-go/flowio/har"
	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/omap"
)

func TestDifferentialDuplicateEntries(t *testing.T) {
	tests := map[string]struct{ input string }{
		"success: last entries wins":               {input: `{"log":{"entries":[1],"entries":[2,3]}}`},
		"success: last log wins":                   {input: `{"log":{"entries":[1]},"log":{"entries":[2,3]}}`},
		"success: earlier invalid entries ignored": {input: `{"log":{"entries":0,"entries":[2,3]}}`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			want := difftest.Python(t, `import json,sys
sys.stdout.write(json.dumps(json.load(sys.stdin)["log"]["entries"], separators=(",", ":")))
`, []byte(tt.input))
			entries, err := har.ReadEntries(bytes.NewBufferString(tt.input))
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.Marshal(entries)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(string(want), string(got)); diff != "" {
				t.Errorf("duplicate entries (-Python +Go):\n%s", diff)
			}
		})
	}
}

func TestDifferentialStartedDateTime(t *testing.T) {
	tests := map[string]struct{ stamp string }{
		"success: UTC":            {"2023-03-29T17:37:42Z"},
		"success: offset":         {"2023-03-29T17:37:42.482-07:00"},
		"success: long fraction":  {"2023-03-29T17:37:42.123456789012Z"},
		"success: naive":          {"2023-03-29T17:37:42"},
		"success: naive fraction": {"2023-03-29T17:37:42.123456789"},
		"success: space":          {"2023-03-29 17:37:42.482+09:00"},
		"success: naive space":    {"2023-03-29 17:37:42.123456"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(map[string]any{
				"startedDateTime": tt.stamp, "time": 0,
				"request":  map[string]any{"method": "GET", "url": "http://example.com/", "httpVersion": "HTTP/1.1", "headers": []any{}},
				"response": map[string]any{"status": 200, "httpVersion": "HTTP/1.1", "headers": []any{}, "content": map[string]string{}},
			})
			if err != nil {
				t.Fatal(err)
			}
			wantData := difftest.Python(t, `import json,sys
from mitmproxy.io.har import request_to_flow
print(json.dumps(request_to_flow(json.load(sys.stdin)).request.timestamp_start))
`, data)
			var want float64
			if err := json.Unmarshal(wantData, &want); err != nil {
				t.Fatal(err)
			}
			f, err := har.RequestToFlow(data)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(want, f.Request.TimestampStart); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestDifferentialGoHAR(t *testing.T) {
	tests := map[string]struct{ method, version, charset, contentEncoding, text, encoding string }{
		"success: HTTP2 gzip and cookies": {method: "POST", version: "http/2.0", charset: "utf-8", contentEncoding: "gzip", text: "hello ü"},
		"success: latin1 and HTTP3":       {method: "GET", version: "HTTP/3", charset: "latin1", text: "café"},
		"success: base64 binary":          {method: "HEAD", version: "HTTP/1.0", text: base64.StdEncoding.EncodeToString([]byte{0, 255, 254}), encoding: "base64"},
		"success: charset fallback":       {method: "PATCH", version: "HTTP/1.1", charset: "unknown", text: "☃"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			headers := []map[string]string{{"name": "Content-Type", "value": "text/plain; charset=" + tt.charset}}
			if tt.contentEncoding != "" {
				headers = append(headers, map[string]string{"name": "Content-Encoding", "value": tt.contentEncoding})
			}
			entry := map[string]any{
				"startedDateTime": "2023-03-29T17:37:42.482-07:00", "time": 123.75,
				"serverIPAddress": "192.0.2.1",
				"request":         map[string]any{"method": tt.method, "url": "http://example.com:8080/hello?a=1", "httpVersion": tt.version, "headers": []map[string]string{{"name": "Cookie", "value": "a=b"}}, "postData": map[string]string{"text": "hello"}},
				"response":        map[string]any{"status": 200, "httpVersion": tt.version, "headers": headers, "content": map[string]string{"text": tt.text, "encoding": tt.encoding}},
			}
			data, err := json.Marshal(map[string]any{"log": map[string]any{"entries": []any{entry}}})
			if err != nil {
				t.Fatal(err)
			}
			want := difftest.Python(t, `import io,json,sys
from mitmproxy.io import FlowReader
from mitmproxy.tools.web.app import flow_to_json
f = flow_to_json(next(FlowReader(io.BytesIO(sys.stdin.buffer.read())).stream()))
f['id']='hardcoded_for_test'; f['timestamp_created']=0
f['client_conn']['id']='hardcoded_for_test'; f['server_conn']['id']='hardcoded_for_test'
sys.stdout.buffer.write(json.dumps(f,ensure_ascii=False,separators=(',',':')).encode('utf8','backslashreplace'))
`, data)
			f, err := flowio.NewReader(bytes.NewReader(data)).Next()
			if err != nil {
				t.Fatal(err)
			}
			obj, err := flowjson.Flow(f)
			if err != nil {
				t.Fatal(err)
			}
			obj.Set("id", "hardcoded_for_test")
			obj.Set("timestamp_created", 0)
			for _, key := range []string{"client_conn", "server_conn"} {
				c, _ := obj.Get(key)
				c.(*omap.Map[any]).Set("id", "hardcoded_for_test")
			}
			got, err := json.Marshal(obj)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(string(want), string(got)); diff != "" {
				t.Errorf("Go-generated HAR import (-Python +Go):\n%s", diff)
			}
		})
	}
}
