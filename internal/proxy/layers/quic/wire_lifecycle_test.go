// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"testing"
	"testing/synctest"

	"github.com/zchee/mitmproxy-go/connection"
)

func TestQUICFixtureDisconnectIdentity(t *testing.T) {
	tests := map[string]struct{ reused bool }{
		"watched connection signals disconnect":          {},
		"reused tuple does not block watched disconnect": {reused: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				observer := &wireObserver{disconnected: make(chan struct{}, 1)}
				watched := connection.NewClient(connection.Address{}, connection.Address{}, 1)
				if err := observer.ClientConnected(t.Context(), watched); err != nil {
					t.Fatal(err)
				}
				disconnected := watched
				if tt.reused {
					if err := observer.ClientDisconnected(t.Context(), watched); err != nil {
						t.Fatal(err)
					}
					disconnected = connection.NewClient(connection.Address{}, connection.Address{}, 2)
					if err := observer.ClientConnected(t.Context(), disconnected); err != nil {
						t.Fatal(err)
					}
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					if err := observer.ClientDisconnected(t.Context(), disconnected); err != nil {
						t.Error(err)
					}
				}()
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Error("fixture disconnect hook blocked on a different connection")
				}
				<-observer.disconnected
				synctest.Wait()
				<-done
			})
		})
	}
}
