// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"
)

func TestUnidirectionalStreamTypeTermination(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	tests := map[string]struct {
		closeConnection bool
		closeCode       ErrorCode
		wantCode        ErrorCode
	}{
		"live connection rejects truncated type":   {wantCode: ErrCodeStreamCreation},
		"normal HTTP connection close is teardown": {closeConnection: true, closeCode: ErrCodeNoError},
		"normal QUIC connection close is teardown": {closeConnection: true},
		"application close preserves its code":     {closeConnection: true, closeCode: ErrCodeRequestCancelled, wantCode: ErrCodeRequestCancelled},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
			t.Cleanup(cancel)
			client, server, ctx := newEndpointPairContexts(t, ctx, nil, cancel, nil)
			release := make(chan struct{})
			propagation := &pausedCancellationContext{Context: server.conn.context(), release: release}
			server.ctx, server.cancel = context.WithCancel(propagation)
			defer func() {
				server.cancel()
				close(release)
				propagation.callbacks.Wait()
			}()
			server.incoming = make(map[uint64]*incomingUniStream)
			stream, err := client.conn.openUniStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// The prefix declares a two-byte integer but supplies only its first
			// byte. Acceptance proves delivery before either FIN or close.
			if _, err := stream.Write([]byte{0x40}); err != nil {
				t.Fatal(err)
			}
			incoming, err := server.conn.acceptUniStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			deadline, _ := ctx.Deadline()
			if err := incoming.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if test.closeConnection {
				if err := client.conn.closeWithError(uint64(test.closeCode)); err != nil {
					t.Fatal(err)
				}
				select {
				case <-server.conn.context().Done():
				case <-ctx.Done():
					t.Fatal("peer connection close was not observed:", ctx.Err())
				}
			} else if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			// Hold asynchronous connection cancellation until classification has
			// finished, excluding Run's competing accept/close observers.
			if server.ctx.Err() != nil {
				t.Fatal("endpoint cancellation escaped the propagation gate")
			}
			server.readUnidirectional(incoming)
			err = server.endError()
			if test.wantCode == 0 {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("normal close classified as %v; want connection teardown", err)
				}
				return
			}
			failure, ok := errors.AsType[*ConnectionError](err)
			if !ok {
				t.Fatalf("stream type termination = %v; want %s", err, test.wantCode)
			}
			if diff := gocmp.Diff(test.wantCode, failure.Code); diff != "" {
				t.Fatalf("stream type termination code (-want +got):\n%s", diff)
			}
			if !test.closeConnection && server.conn.context().Err() == nil {
				t.Fatal("truncated stream type did not abort the live connection")
			}
		})
	}
}
