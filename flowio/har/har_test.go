// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package har_test

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/flowio/flowjson"
	"github.com/zchee/mitmproxy-go/flowio/har"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/omap"
)

func TestFixHeaders(t *testing.T) {
	tests := map[string]struct {
		input string
		want  httpmsg.Headers
		err   bool
	}{
		"success: named fields":     {input: `[{"name":"X-Foo","value":"a"},{"name":"x-foo","value":"b"}]`, want: httpmsg.Headers{{Name: []byte("X-Foo"), Value: []byte("a")}, {Name: []byte("x-foo"), Value: []byte("b")}}},
		"success: pairs":            {input: `[["X-Foo","a"],["x-foo","b","ignored"]]`, want: httpmsg.Headers{{Name: []byte("X-Foo"), Value: []byte("a")}, {Name: []byte("x-foo"), Value: []byte("b")}}},
		"success: empty":            {input: `[]`, want: httpmsg.Headers{}},
		"error: missing pair value": {input: `[["X-Foo"]]`, err: true},
		"error: missing name":       {input: `[{"value":"a"}]`, err: true},
		"error: nonstring value":    {input: `[{"name":"x","value":4}]`, err: true},
		"error: null":               {input: `[null]`, err: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := har.FixHeaders(jsontext.Value(tt.input))
			if tt.err {
				if _, ok := errors.AsType[*har.HeaderError](err); !ok {
					t.Fatalf("error = %v, want HeaderError", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Error(diff)
			}
		})
	}
	// Upstream test_corrupt uses this malformed pair fixture.
	data, err := os.ReadFile("../../testdata/mitmproxy/corrupted_har/broken_headers.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Headers jsontext.Value `json:"headers"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	var headerErr *har.HeaderError
	if _, err := har.FixHeaders(document.Headers); !errors.As(err, &headerErr) {
		t.Fatalf("corrupt fixture error = %v", err)
	}
}

// Every pair from upstream test_har_to_flow is checked; only its four volatile
// fields are normalised, exactly as hardcode_variable_fields_for_tests does.
func TestHARToFlow(t *testing.T) {
	paths, err := filepath.Glob("../../testdata/mitmproxy/har_files/*.har")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 8 {
		t.Fatalf("fixture count = %d, want 8", len(paths))
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			wantData, err := os.ReadFile(path[:len(path)-4] + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var want []any
			if err := json.Unmarshal(wantData, &want); err != nil {
				t.Fatal(err)
			}
			got := make([]any, 0)
			for f, err := range flowio.NewReader(bytes.NewReader(data)).All() {
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
				raw, err := json.Marshal(obj)
				if err != nil {
					t.Fatal(err)
				}
				var value any
				if err := json.Unmarshal(raw, &value); err != nil {
					t.Fatal(err)
				}
				got = append(got, value)
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("HAR import (-upstream +Go):\n%s", diff)
			}
		})
	}
}

func TestRequestToFlowMalformed(t *testing.T) {
	tests := map[string]struct{ input string }{
		"error: empty entry":       {`{}`},
		"error: invalid timestamp": {`{"startedDateTime":"never","time":0,"request":{},"response":{}}`},
		"error: null entry":        {`null`},
		"error: truncated":         {`{"request":`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := har.RequestToFlow(jsontext.Value(tt.input)); err == nil {
				t.Fatal("malformed entry accepted")
			}
		})
	}
}
