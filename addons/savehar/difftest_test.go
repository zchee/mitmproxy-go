// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package savehar

import (
	"bytes"
	"compress/zlib"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func TestDifferentialExport(t *testing.T) {
	tests := map[string]struct {
		ws, binary, missing bool
		timestamp           float64
	}{
		"success: ordinary":         {timestamp: 946681206.1234567},
		"success: websocket":        {ws: true, timestamp: 1.9999999},
		"success: binary wire text": {binary: true, timestamp: -0.0000005},
		"success: missing body":     {missing: true, timestamp: 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := testflow.TFlow(testflow.WithResponse)
			f.Request.TimestampStart = tt.timestamp
			if tt.ws {
				f = testflow.TWebSocketFlow()
				f.Request.TimestampStart = tt.timestamp
			}
			if tt.binary {
				f.Request.Headers.Add("X-Binary", string([]byte{255, 254}))
				f.Request.Method = "get" + string([]byte{255})
				f.Response.RawContent = append([]byte("mostly text: "), 255)
			}
			if tt.missing {
				f.Request.Method = "POST"
				f.Request.RawContent = nil
				f.Response.RawContent = nil
			}
			var dump bytes.Buffer
			if err := flowio.NewWriter(&dump).Add(f); err != nil {
				t.Fatal(err)
			}
			want := difftest.Python(t, `import io,json,sys
from mitmproxy.io import FlowReader
from mitmproxy.addons.savehar import SaveHar
from mitmproxy import version
version.VERSION='1.2.3'
flows=list(FlowReader(io.BytesIO(sys.stdin.buffer.read())).stream())
sys.stdout.buffer.write(json.dumps(SaveHar().make_har(flows)).encode())
`, dump.Bytes())
			got, err := New(options.New(), "1.2.3").marshalHAR(t.Context(), []flow.Flow{f})
			if err != nil {
				t.Fatal(err)
			}
			var wantJSON, gotJSON any
			if err := json.Unmarshal(want, &wantJSON, jsontext.AllowInvalidUTF8(true)); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(got, &gotJSON, jsontext.AllowInvalidUTF8(true)); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(wantJSON, gotJSON); diff != "" {
				t.Error(diff)
			}
			if tt.binary {
				escaped := []byte{'\\', 'u', 'd', 'c', 'f', 'f', '\\', 'u', 'd', 'c', 'f', 'e'}
				if !bytes.Contains(got, escaped) {
					t.Fatal("binary headers did not retain surrogate escapes")
				}
			}
		})
	}
}

func TestDifferentialCompressedFixture(t *testing.T) {
	compressed, err := os.ReadFile("../../testdata/mitmproxy/flows/compressed.zhar")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.LimitReader(reader, 256<<20))
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	want := difftest.Python(t, `import io,json,sys
from mitmproxy.io import FlowReader
from mitmproxy.addons.savehar import SaveHar
from mitmproxy import version
version.VERSION='1.2.3'
flows=list(FlowReader(io.BytesIO(sys.stdin.buffer.read())).stream())
assert len(flows)==2
sys.stdout.buffer.write(json.dumps(SaveHar().make_har(flows)).encode())
`, data)
	var flows []flow.Flow
	for f, err := range flowio.NewReader(bytes.NewReader(data)).All() {
		if err != nil {
			t.Fatal(err)
		}
		flows = append(flows, f)
	}
	path := filepath.Join(t.TempDir(), "out.zhar")
	if err := New(options.New(), "1.2.3").exportHAR(t.Context(), flows, command.Path(path)); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err = zlib.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.LimitReader(reader, 256<<20))
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	var wantJSON, gotJSON any
	if err := json.Unmarshal(want, &wantJSON); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &gotJSON); err != nil {
		t.Fatal(err)
	}
	if !cmp.Equal(wantJSON, gotJSON) {
		t.Fatal("compressed fixture roundtrip differs from Python")
	}
}

func TestDifferentialGoExportImport(t *testing.T) {
	f := testflow.TFlow(testflow.WithResponse)
	f.Request.Method = "POST"
	data, err := New(options.New(), "1.2.3").marshalHAR(t.Context(), []flow.Flow{f})
	if err != nil {
		t.Fatal(err)
	}
	want := difftest.Python(t, `import io,json,sys
from mitmproxy.io import FlowReader
from mitmproxy.tools.web.app import flow_to_json
fs=list(FlowReader(io.BytesIO(sys.stdin.buffer.read())).stream())
assert len(fs)==1
print(json.dumps([fs[0].request.method,fs[0].request.get_content().decode(),fs[0].response.get_content().decode()]))
`, data)
	if diff := cmp.Diff("[\"POST\", \"content\", \"message\"]\n", string(want)); diff != "" {
		t.Error(diff)
	}
}
