// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package contentviewsdraft

import (
	json "encoding/json/v2"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestHTTP3FramesDifferential(t *testing.T) {
	tests := http3Vectors(t)
	cases := make(map[string]struct {
		Data []byte `json:"data"`
		Uni  bool   `json:"uni"`
	}, len(tests))
	for name, tt := range tests {
		cases[name] = struct {
			Data []byte `json:"data"`
			Uni  bool   `json:"uni"`
		}{tt.data, tt.uni}
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
from mitmproxy.contentviews._view_http3 import http3
from mitmproxy.tcp import TCPMessage
from mitmproxy.test import tflow

result = {"texts": {}, "priority": http3.render_priority(b"random stuff", Metadata())}
for name, case in json.load(sys.stdin).items():
    data = base64.b64decode(case["data"] or "")
    flow = tflow.ttcpflow(messages=[TCPMessage(from_client=len(data)>16, content=data)])
    flow.metadata["quic_is_unidirectional"] = case["uni"]
    result["texts"][name] = http3.prettify(b"", Metadata(flow=flow, tcp_message=flow.messages[0]))
json.dump(result, sys.stdout)
`, input)
	var reference struct {
		Texts    map[string]string `json:"texts"`
		Priority float64           `json:"priority"`
	}
	if err := json.Unmarshal(output, &reference); err != nil {
		t.Fatal(err)
	}
	t.Run("upstream", func(t *testing.T) {
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				want, found := reference.Texts[name]
				if !found {
					t.Fatal("missing Python HTTP/3 result")
				}
				got, err := (HTTP3Frames{}).Prettify(nil, http3Metadata(tt.data, tt.uni))
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(normalizeQPACKError(want), normalizeQPACKError(got)); diff != "" {
					t.Fatal(diff)
				}
			})
		}
		t.Run("test_render_priority", func(t *testing.T) {
			if got := (HTTP3Frames{}).RenderPriority([]byte("random stuff"), contentviews.Metadata{}); got != reference.Priority {
				t.Fatalf("priority=%v want=%v", got, reference.Priority)
			}
		})
	})
}

// Only the different QPACK libraries' diagnostic detail is unspecified.
func normalizeQPACKError(text string) string {
	lines := strings.SplitAfter(text, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "HEADERS Frame (error: ") && strings.HasSuffix(strings.TrimSuffix(line, "\n"), ")") {
			lines[i] = "HEADERS Frame (error: QPACK)"
			if strings.HasSuffix(line, "\n") {
				lines[i] += "\n"
			}
		}
	}
	return strings.Join(lines, "")
}
