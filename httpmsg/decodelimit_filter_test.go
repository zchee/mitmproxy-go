// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg_test

import (
	"testing"

	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/httpmsg"
	netencoding "github.com/zchee/mitmproxy-go/internal/netutil/encoding"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

// TestDecodeLimitFilterSeesRawBytes checks that a body-matching filter
// evaluates a body over the decode limit against the raw bytes, because
// filters read bodies through ContentOrRaw. The response body is a gzip
// stream that decodes to 2 MiB, followed by a marker the gzip decoder
// ignores as trailing data: the marker is found only when the raw bytes
// are searched. The test sets the process-global decode limit, so it must
// not run in parallel and restores the previous value.
func TestDecodeLimitFilterSeesRawBytes(t *testing.T) {
	const marker = "RAWMARKER0"
	raw, err := netencoding.Encode(make([]byte, 2<<20), "gzip")
	if err != nil {
		t.Fatalf("Encode(gzip) error: %v", err)
	}
	raw = append(raw, marker...)

	f := testflow.TFlow(testflow.WithResponse)
	f.Response.Headers.Set("content-encoding", "gzip")
	f.Response.RawContent = raw

	expr, err := filter.Parse("~bs " + marker)
	if err != nil {
		t.Fatalf("filter.Parse error: %v", err)
	}

	tests := map[string]struct {
		limit int64
		want  bool
	}{
		"success: raw bytes searched over a 1 MiB limit":    {limit: 1 << 20, want: true},
		"success: decoded bytes searched under the default": {limit: 256 << 20, want: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			previous := httpmsg.SetDecodeLimit(tt.limit)
			t.Cleanup(func() { httpmsg.SetDecodeLimit(previous) })
			if got := filter.Match(expr, f); got != tt.want {
				t.Errorf("Match(~bs %s) = %v with limit %d, want %v", marker, got, tt.limit, tt.want)
			}
		})
	}
}
