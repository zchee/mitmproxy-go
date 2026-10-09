// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"runtime"
	"testing"
	"time"
)

func awaitFixtureSignal[T any](t *testing.T, signal <-chan T, operation string, progress func() string) T {
	t.Helper()
	select {
	case result := <-signal:
		return result
	case <-time.After(30 * time.Second):
		stack := make([]byte, 1<<20)
		t.Fatalf("waiting for %s hung; %s\n%s", operation, progress(), stack[:runtime.Stack(stack, true)])
		var zero T
		return zero
	}
}
