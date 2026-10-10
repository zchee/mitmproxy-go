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
	quic "github.com/quic-go/quic-go"
)

func TestEndpointInitializationCloseCause(t *testing.T) {
	// Regression: initialization can observe a transport close before the
	// connection-context and accept observers publish its normalized cause.
	tests := map[string]struct {
		code   ErrorCode
		remote bool
	}{
		"success: local HTTP3 no error": {code: ErrCodeNoError},
		"success: local QUIC no error":  {},
		"error: local protocol close":   {code: ErrCodeGeneralProtocol},
		"error: remote protocol close":  {code: ErrCodeGeneralProtocol, remote: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
			t.Cleanup(cancel)
			client, server, ctx := newEndpointPairContexts(t, ctx, nil, cancel, nil)
			closer := client
			if test.remote {
				closer = server
			}
			if err := closer.conn.closeWithError(uint64(test.code)); err != nil {
				t.Fatal("close connection:", err)
			}
			select {
			case <-client.conn.context().Done():
			case <-ctx.Done():
				t.Fatal("connection close was not observed:", ctx.Err())
			}
			// Leave the competing observers unstarted to pin initialization as
			// the first publisher, rather than relying on scheduler timing.
			client.ctx, client.cancel = context.WithCancel(ctx)
			t.Cleanup(client.cancel)
			err := client.initialize()
			closeErr, ok := errors.AsType[*quic.ApplicationError](err)
			if !ok {
				t.Fatalf("initialization error = %v, want application close", err)
			}
			if diff := gocmp.Diff(test.remote, closeErr.Remote); diff != "" {
				t.Fatalf("close origin (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(test.code, ErrorCode(closeErr.ErrorCode)); diff != "" {
				t.Fatalf("transport close code (-want +got):\n%s", diff)
			}
			client.fail(err)
			got := client.endError()
			if test.code == 0 || test.code == ErrCodeNoError {
				if !errors.Is(got, io.EOF) {
					t.Fatalf("initialization termination = %v, want EOF", got)
				}
				return
			}
			failure, ok := errors.AsType[*ConnectionError](got)
			if !ok {
				t.Fatalf("initialization termination = %v, want ConnectionError", got)
			}
			if diff := gocmp.Diff(test.code, failure.Code); diff != "" {
				t.Fatalf("connection close code (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(closeErr.Error(), failure.Message); diff != "" {
				t.Fatalf("connection diagnostic (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEndpointFailurePreservesNonApplicationCause(t *testing.T) {
	// Preservation: normalizing transport closes must not replace an already
	// classified protocol error or any caller-owned non-application cause.
	tests := map[string]struct{ err error }{
		"error: connection protocol": {err: connectionError(ErrCodeGeneralProtocol, "original protocol failure")},
		"error: context canceled":    {err: context.Canceled},
		"error: context deadline":    {err: context.DeadlineExceeded},
		"success: EOF":               {err: io.EOF},
		"error: plain cause":         {err: errors.New("original terminal failure")},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
			t.Cleanup(cancel)
			client, _, ctx := newEndpointPairContexts(t, ctx, nil, cancel, nil)
			client.ctx, client.cancel = context.WithCancel(ctx)
			t.Cleanup(client.cancel)
			client.fail(test.err)
			if got := client.endError(); got != test.err {
				t.Fatalf("terminal cause = %v (%T), want the original %v (%T)", got, got, test.err, test.err)
			}
		})
	}
}

func TestEndpointRunAfterLocalCleanClose(t *testing.T) {
	// Certification: Run joins its workers with a clean terminal cause even
	// when the borrowed transport was closed before its critical streams open.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
	t.Cleanup(cancel)
	client, _, ctx := newEndpointPairContexts(t, ctx, nil, cancel, nil)
	if err := client.conn.closeWithError(uint64(ErrCodeNoError)); err != nil {
		t.Fatal("close connection:", err)
	}
	if err := client.Run(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("Run after local clean close = %v, want EOF", err)
	}
	select {
	case <-client.Done():
	default:
		t.Fatal("Run returned before endpoint cleanup finished")
	}
}
