// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layertest

import (
	"runtime"
	"testing"
	"time"
)

func TestMemoryPipeReleasesClosedEndpoints(t *testing.T) {
	tests := map[string]struct{ halfClose bool }{
		"success: full close releases future deadlines": {},
		"success: half close releases future deadlines": {halfClose: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			collected := make(chan struct{}, 4)
			t.Run("allocate and close", func(t *testing.T) {
				a, b := MemoryPipe(t)
				for _, endpoint := range []*memoryConn{a.(*memoryConn), b.(*memoryConn)} {
					// Observe the underlying pipes, not wrappers that timers do not retain.
					runtime.SetFinalizer(endpoint.Conn, func(any) { collected <- struct{}{} })
					runtime.SetFinalizer(endpoint.writer, func(any) { collected <- struct{}{} })
					if err := endpoint.SetDeadline(time.Now().Add(time.Hour)); err != nil {
						t.Fatal(err)
					}
				}
				if tt.halfClose {
					if err := a.CloseWrite(); err != nil {
						t.Fatal(err)
					}
					if err := b.CloseWrite(); err != nil {
						t.Fatal(err)
					}
				}
				if err := a.Close(); err != nil {
					t.Fatal(err)
				}
				if err := b.Close(); err != nil {
					t.Fatal(err)
				}
			})
			// Child cleanup has dropped its references. Future deadlines cannot fire
			// during this hang detector, so collection proves close stopped them.
			runtime.GC()
			timer := time.NewTimer(Timeout)
			defer timer.Stop()
			for i := range 4 {
				select {
				case <-collected:
				case <-timer.C:
					t.Fatalf("collected %d of 4 closed endpoints with future deadlines", i)
				}
			}
		})
	}
}
