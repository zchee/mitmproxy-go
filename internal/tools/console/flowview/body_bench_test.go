// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowview

import (
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

func BenchmarkFlowViewBody(b *testing.B) {
	request, err := httpmsg.MakeRequest("POST", "https://example.test/", []byte(strings.Repeat("x", 32<<20)), nil)
	if err != nil {
		b.Fatal(err)
	}
	f := flow.NewHTTPFlow(connection.NewClient(connection.Address{}, connection.Address{}, 1), connection.NewServer(nil), false)
	f.Request = request
	m := New(b.Context(), nil)
	m.Resize(80, 24)
	m.SetSnapshot(contract.Snapshot{Focused: f, Detail: contract.DetailOptions{DefaultContentView: "raw", LineCutoff: 512}})
	m.View()
	b.ReportAllocs()
	for b.Loop() {
		m.Resize(80, 24)
		m.View()
	}
}
