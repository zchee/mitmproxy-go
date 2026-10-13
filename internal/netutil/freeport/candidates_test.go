// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestPortCandidateSelection(t *testing.T) {
	entropy := errors.New("entropy unavailable")
	tests := map[string]struct {
		bounds   portRange
		excluded []portRange
		want     []int
		index    int
		cause    error
		fail     bool
	}{
		"success: TCP exclusions":                    {bounds: portRange{50000, 50004}, excluded: []portRange{{50000, 50002}}, want: []int{50003, 50004}},
		"success: UDP exclusions":                    {bounds: portRange{50000, 50004}, excluded: []portRange{{50002, 50004}}, want: []int{50000, 50001}},
		"success: overlapping exclusions":            {bounds: portRange{50000, 50009}, excluded: []portRange{{50000, 50004}, {50003, 50008}}, want: []int{50009}},
		"success: denied interval wider than budget": {bounds: portRange{50000, 50100}, excluded: []portRange{{50000, 50099}}, want: []int{50100}},
		"success: empty tables":                      {bounds: portRange{50000, 50002}, want: []int{50000, 50001, 50002}},
		"error: empty intersection":                  {bounds: portRange{50000, 49999}, fail: true},
		"error: disjoint bounds":                     {bounds: portRange{50100, 50000}, fail: true},
		"error: invalid lower bound":                 {bounds: portRange{0, 50000}, fail: true},
		"error: invalid upper bound":                 {bounds: portRange{50000, 65536}, fail: true},
		"error: fully excluded":                      {bounds: portRange{50000, 50100}, excluded: []portRange{{50000, 50100}}, fail: true},
		"error: sampler failure":                     {bounds: portRange{50000, 50002}, cause: entropy},
		"error: negative sampler index":              {bounds: portRange{50000, 50002}, index: -1},
		"error: oversized sampler index":             {bounds: portRange{50000, 50002}, index: 3},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cursor, err := newPortCandidates(t.Context(), func(context.Context) (pairDomain, error) {
				return pairDomain{available: true, bounds: test.bounds, excluded: test.excluded}, nil
			}, func(int) (int, error) { return test.index, test.cause })
			if test.fail {
				if cursor != nil || err == nil {
					t.Fatalf("invalid domain returned cursor=%v error=%v", cursor, err)
				}
				if _, ok := errors.AsType[*net.OpError](err); !ok {
					t.Fatalf("domain error not typed: %T", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.cause != nil || test.index != 0 {
				port, err := cursor.Next(t.Context())
				if port != 0 || err == nil || test.cause != nil && !errors.Is(err, test.cause) {
					t.Fatalf("sampler error lost: port=%d error=%v", port, err)
				}
				if _, ok := errors.AsType[*net.OpError](err); !ok {
					t.Fatalf("sampling error not typed: %T", err)
				}
				return
			}
			var got []int
			for {
				port, err := cursor.Next(t.Context())
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, port)
			}
			slices.Sort(got)
			if diff := gocmp.Diff(test.want, got); diff != "" {
				t.Fatalf("candidate domain (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPortCandidateDiscoveryCancellation(t *testing.T) {
	tests := map[string]struct {
		beforeDiscovery bool
		duringSelection bool
	}{
		"error: before discovery":          {beforeDiscovery: true},
		"error: waiting shares one worker": {},
		"error: sampling cancellation":     {duringSelection: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var calls atomic.Int32
			started, release := make(chan struct{}), make(chan struct{})
			discover := newPairDiscovery(func() pairDomain {
				calls.Add(1)
				close(started)
				<-release
				return pairDomain{available: true, bounds: portRange{50000, 50001}}
			})
			if test.beforeDiscovery {
				cancel()
				cursor, err := newPortCandidates(ctx, discover, nil)
				if cursor != nil || !errors.Is(err, context.Canceled) || calls.Load() != 0 {
					t.Fatalf("precancelled discovery: cursor=%v error=%v workers=%d", cursor, err, calls.Load())
				}
				return
			}
			if test.duringSelection {
				close(release)
				cursor, err := newPortCandidates(ctx, discover, func(int) (int, error) { cancel(); return 0, nil })
				if err != nil {
					t.Fatal(err)
				}
				port, err := cursor.Next(ctx)
				if port != 0 || !errors.Is(err, context.Canceled) {
					t.Fatalf("sampling cancellation: port=%d error=%v", port, err)
				}
				return
			}
			result := make(chan error, 1)
			go func() {
				cursor, err := newPortCandidates(ctx, discover, nil)
				if cursor != nil {
					result <- errors.New("cancelled discovery returned a cursor")
					return
				}
				result <- err
			}()
			<-started
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("waiting cancellation: %v", err)
				}
			case <-time.After(time.Second):
				t.Error("cancelled discovery caller failed to return")
			}
			close(release)
			for range 2 {
				cursor, err := newPortCandidates(t.Context(), discover, func(int) (int, error) { return 0, nil })
				if err != nil {
					t.Fatal(err)
				}
				if port, err := cursor.Next(t.Context()); port != 50000 || err != nil {
					t.Fatalf("reusable cached discovery: port=%d error=%v", port, err)
				}
			}
			if calls.Load() != 1 {
				t.Fatalf("shared discovery workers=%d, want 1", calls.Load())
			}
		})
	}
}

func TestPortCandidateDiscoveryFallback(t *testing.T) {
	cause := errors.New("discovery cancelled")
	tests := map[string]struct {
		domain pairDomain
		cause  error
		want   int
	}{
		"success: unavailable discovery":                         {want: attempts},
		"success: unavailable bounds retain combined exclusions": {domain: pairDomain{excluded: []portRange{{49152, 65534}}}, want: 1},
		"success: cached fallback bounds":                        {domain: pairDomain{bounds: portRange{49152, 65535}}, want: attempts},
		"success: complete discovery uses intersection":          {domain: pairDomain{available: true, bounds: portRange{50000, 50001}}, want: 2},
		"error: caller discovery cause":                          {cause: cause},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cursor, err := newPortCandidates(t.Context(), func(context.Context) (pairDomain, error) {
				return test.domain, test.cause
			}, func(size int) (int, error) { return size - 1, nil })
			if test.cause != nil {
				if cursor != nil || !errors.Is(err, test.cause) {
					t.Fatalf("discovery failure: cursor=%v error=%v", cursor, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			seen := make(map[int]bool)
			for range test.want {
				port, err := cursor.Next(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				bounds := test.domain.bounds
				if bounds == (portRange{}) {
					bounds = portRange{49152, 65535}
				}
				if port < bounds.first || port > bounds.last || inPortRanges(port, test.domain.excluded) || seen[port] {
					t.Fatalf("repeated, excluded or out-of-bounds candidate %d", port)
				}
				seen[port] = true
			}
			if port, err := cursor.Next(t.Context()); port != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("budget/domain exhaustion: port=%d error=%v", port, err)
			}
		})
	}
}
