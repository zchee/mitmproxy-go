// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestClientLimiter(t *testing.T) {
	tests := map[string]struct {
		initial int
		limit   int
	}{
		"success: finite cap": {initial: 2, limit: 2},
		"success: zero value counts clients before lowering cap": {initial: 0, limit: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var limiter ClientLimiter
			limiter.SetLimit(tt.initial)
			for range 2 {
				if admitted, _ := limiter.acquire(); !admitted {
					t.Fatal("client unexpectedly refused")
				}
			}
			limiter.SetLimit(tt.limit)
			if admitted, limit := limiter.acquire(); admitted || limit != int64(tt.limit) {
				t.Fatalf("over-cap admission = %v, %d", admitted, limit)
			}
			if diff := gocmp.Diff(int64(2), limiter.active.Load()); diff != "" {
				t.Fatalf("refusal changed reservations (-want +got):\n%s", diff)
			}
			limiter.release()
			limiter.release()
			if admitted, _ := limiter.acquire(); !admitted {
				t.Fatal("released capacity not reusable")
			}
			limiter.release()
			limiter.SetLimit(0)
			for range 4 {
				if admitted, _ := limiter.acquire(); !admitted {
					t.Fatal("zero cap is not unlimited")
				}
			}
			for range 4 {
				limiter.release()
			}
			if got := limiter.active.Load(); got != 0 {
				t.Fatalf("reservations after release = %d", got)
			}
		})
	}
}

func TestClientLimiterConcurrent(t *testing.T) {
	var limiter ClientLimiter
	limiter.SetLimit(7)
	var workers sync.WaitGroup
	results := make(chan bool, 64)
	for range 64 {
		workers.Go(func() {
			admitted, _ := limiter.acquire()
			results <- admitted
		})
	}
	workers.Wait()
	close(results)
	admitted := 0
	for result := range results {
		if result {
			admitted++
		}
	}
	if diff := gocmp.Diff(7, admitted); diff != "" {
		t.Fatalf("concurrent reservation count (-want +got):\n%s", diff)
	}
	for range admitted {
		limiter.release()
	}
	if got := limiter.active.Load(); got != 0 {
		t.Fatalf("reservation leak = %d", got)
	}
}
