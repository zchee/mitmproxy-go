// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/httpmsg"
)

func TestLazyServerFailedSend(t *testing.T) {
	failure := errors.New("connection refused")
	server := &lazyServer{
		ready: make(chan struct{}),
		acquire: func(context.Context, *httpmsg.Request) (ServerEndpoint, error) {
			return nil, failure
		},
	}
	head := requestHead("0")
	err := server.Send(t.Context(), head)
	if err == nil || err.Error() != failure.Error() {
		t.Fatalf("failed acquisition Send = %v, want %q", err, failure)
	}
	driver := &streamDriver{stream: &httpStream{id: head.ID}}
	turn := &driverTurn{output: streamOutput{events: []Event{head}}, pending: true}
	source, result := driver.acknowledge(0, driverWritten{turn: turn, err: err})
	want := ResponseProtocolError{ID: head.ID, Code: ConnectFailed, Message: failure.Error()}
	if source != 1 || result.err != nil {
		t.Fatalf("failed acknowledgement = (%d, %+v), want server protocol event", source, result)
	}
	if diff := gocmp.Diff(Event(want), result.event); diff != "" {
		t.Fatalf("acquisition failure (-want +got):\n%s", diff)
	}
	if err := server.Send(t.Context(), RequestEndOfMessage{ID: head.ID}); err != nil {
		t.Fatalf("trailing event after failed acquisition: %v", err)
	}
}
