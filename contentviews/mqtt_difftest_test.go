// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package contentviews

import (
	json "encoding/json/v2"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestMQTTDifferential(t *testing.T) {
	tests := map[string]struct{ data []byte }{
		"test_mqtt_malformed/c0ffffffff": {[]byte{0xc0, 0xff, 0xff, 0xff, 0xff}},
	}
	for name, tt := range mqttVectors() {
		tests["test_view_mqtt/"+name] = struct{ data []byte }{tt.data}
	}
	cases := make(map[string][]byte, len(tests))
	for name, tt := range tests {
		cases[name] = tt.data
	}
	input, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	output := difftest.Python(t, `
import base64
import json
import sys
from mitmproxy.contentviews import Metadata
from mitmproxy.contentviews._view_mqtt import mqtt

result = {}
for name, encoded in json.load(sys.stdin).items():
    try:
        result[name] = {"text": mqtt.prettify(base64.b64decode(encoded), Metadata()), "failed": False}
    except Exception:
        result[name] = {"text": "", "failed": True}
json.dump(result, sys.stdout)
`, input)
	var reference map[string]struct {
		Text   string `json:"text"`
		Failed bool   `json:"failed"`
	}
	if err := json.Unmarshal(output, &reference); err != nil {
		t.Fatal(err)
	}
	t.Run("upstream", func(t *testing.T) {
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				want, found := reference[name]
				if !found {
					t.Fatal("missing Python result")
				}
				got, err := (MQTT{}).Prettify(tt.data, Metadata{})
				if (err != nil) != want.Failed {
					t.Fatalf("error mismatch: Go=%v Python failed=%v", err, want.Failed)
				}
				if diff := cmp.Diff(want.Text, got); diff != "" {
					t.Fatal(diff)
				}
			})
		}
	})
}
