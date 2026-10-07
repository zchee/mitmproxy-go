// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnslayer

import (
	"context"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
)

func TestValidFrameBeforeMalformedFrame(t *testing.T) {
	s := newSession(t, false, &observer{request: func(_ context.Context, f *flow.DNSFlow) error { f.Response = f.Request.Succeed(nil); return nil }})
	s.start(t)
	wire := append(frame(t, query(1)), []byte{0, 12, 0, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}...)
	if _, err := s.client.Write(wire); err != nil {
		t.Fatal(err)
	}
	if err := await(t, s.done); err == nil {
		t.Fatal("malformed second frame accepted")
	}
	await(t, s.finished)
	if len(s.observed.flows) != 1 || s.observed.flows[0].Request.ID != 1 || s.observed.flows[0].Live {
		t.Fatal("earlier complete frame was not dispatched before closure")
	}
	if diff := gocmp.Diff([]string{"dns_request", "dns_response"}, s.observed.events); diff != "" {
		t.Fatal(diff)
	}
	if !strings.Contains(s.logs.String(), "sent an invalid message:") {
		t.Fatal(s.logs.String())
	}
}
