// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
)

func TestQUICWireEstablishedPublication(t *testing.T) {
	tests := map[string]struct{}{"success: delayed server established hook": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				o := &wireObserver{
					events:            []string{"hello", "start-client", "established-client", "start-server"},
					serverEstablished: make(chan struct{}, 1),
				}
				release := make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				published := make(chan struct{})
				// Gate asynchronous propagation just as a handshake completion can
				// be pending after the origin has accepted the connection.
				context.AfterFunc(ctx, func() {
					<-release
					_ = o.TLSEstablishedServer(t.Context(), &hookdata.TLS{})
					close(published)
				})
				cancel()
				synctest.Wait()
				compared := make(chan struct{})
				go func() {
					wireAwaitServerEstablished(t, o)
					close(compared)
				}()
				synctest.Wait()
				select {
				case <-compared:
					t.Error("hook comparison became ready before established-server publication")
				default:
				}
				unblock()
				wireAwait(t, published)
				wireAwait(t, compared)
				want := []string{"hello", "start-client", "established-client", "start-server", "established-server"}
				if diff := gocmp.Diff(want, o.events); diff != "" {
					t.Error(diff)
				}
			})
		})
	}
}
