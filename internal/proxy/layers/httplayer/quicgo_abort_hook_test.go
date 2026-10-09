// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
)

func TestHTTP3AbortCancelledErrorHookRetry(t *testing.T) {
	// Cancellation-injected stream-level regression: an aborted dispatch must
	// not suppress the connection owner's terminal hook for a streamed response.
	addon := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
		if name == "responseheaders" {
			f.Response.Stream = true
		}
	}}
	stream, master := newTestStream(t, addon)
	drainStream(t, stream, requestHead("0"))
	drainStream(t, stream, RequestEndOfMessage{ID: stream.id})
	drainStream(t, stream, responseHead("6"))
	drainStream(t, stream, ResponseData{ID: stream.id, Data: []byte("123")})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := stream.fail(ctx, "remote response abort", ClientDisconnected); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error dispatch = %v, want context cancellation", err)
	}
	if stream.errorHook {
		t.Fatal("cancelled dispatch marked the error hook published")
	}
	if _, err := stream.fail(t.Context(), "remote response abort", ClientDisconnected); err != nil {
		t.Fatal("terminal error dispatch:", err)
	}
	if _, err := stream.fail(t.Context(), "remote response abort", ClientDisconnected); err != nil {
		t.Fatal("repeated terminal error:", err)
	}
	if err := master.Do(t.Context(), func(context.Context) error {
		want := []string{"requestheaders", "request", "responseheaders", "error"}
		if diff := gocmp.Diff(want, addon.calls); diff != "" {
			t.Errorf("hooks (-want +got):\n%s", diff)
		}
		if stream.flow.Error == nil || stream.flow.Error.Msg != "remote response abort" || stream.flow.Live {
			t.Errorf("terminal flow error=%v live=%t", stream.flow.Error, stream.flow.Live)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
