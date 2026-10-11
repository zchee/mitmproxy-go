// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

// TestPacketRouterRetention certifies exact LRU order, allocation-free misses,
// and admission/reply interleavings without changing source authentication.
func TestPacketRouterRetention(t *testing.T) {
	tests := map[string]struct {
		source, destination netip.Addr
		refresh             string
		admission           bool
	}{
		"success: IPv4 oldest evicted":                    {source: netip.MustParseAddr("10.1.0.1")},
		"success: IPv6 oldest evicted":                    {source: netip.MustParseAddr("2001:db8::1")},
		"success: IPv4 destination hit refreshed":         {source: netip.MustParseAddr("10.1.0.1"), refresh: "hit"},
		"success: IPv6 destination hit refreshed":         {source: netip.MustParseAddr("2001:db8::1"), refresh: "hit"},
		"success: IPv4 last sender and relearn refreshed": {source: netip.MustParseAddr("10.1.0.1"), refresh: "relearn"},
		"success: IPv6 last sender and relearn refreshed": {source: netip.MustParseAddr("2001:db8::1"), refresh: "relearn"},
		"success: IPv4 eviction and admitted relearning":  {source: netip.MustParseAddr("10.1.0.1"), destination: netip.MustParseAddr("198.51.100.7"), admission: true},
		"success: IPv6 eviction and admitted relearning":  {source: netip.MustParseAddr("2001:db8::1"), destination: netip.MustParseAddr("2001:db8:1::1"), admission: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.admission {
				testRetentionAdmission(t, test.source, test.destination)
				return
			}
			router := newPacketRouter(2, slog.New(slog.DiscardHandler))
			source := test.source
			for i := range maxLearnedSources {
				router.mu.Lock()
				router.learnLocked(source, 1)
				router.mu.Unlock()
				assertRetentionSize(t, router, i+1)
				source = source.Next()
			}
			victim := test.source
			switch test.refresh {
			case "hit":
				if got := router.peerFor(test.source); got != 1 {
					t.Fatalf("hit owner = %d, want 1", got)
				}
				victim = victim.Next()
			case "relearn":
				router.mu.Lock()
				router.learnLocked(test.source, 0)
				router.mu.Unlock()
				if got := router.sources[test.source].Value.(*sourceRoute).peer; got != 0 {
					t.Fatalf("last sender = %d, want 0", got)
				}
				victim = victim.Next()
			}
			if allocations := testing.AllocsPerRun(100, func() { router.peerFor(source.Next()) }); allocations != 0 {
				t.Fatalf("miss allocations = %v, want 0", allocations)
			}
			assertRetentionSize(t, router, maxLearnedSources)
			router.mu.Lock()
			router.learnLocked(source, 0)
			router.mu.Unlock()
			assertRetentionSize(t, router, maxLearnedSources)
			if _, found := router.sources[victim]; found {
				t.Fatalf("LRU victim %v remained learned", victim)
			}
			if got := router.peerFor(victim); got != 0 {
				t.Fatalf("evicted owner = %d, want fallback 0", got)
			}
			if _, found := router.sources[victim]; found {
				t.Fatal("lookup relearned an evicted source")
			}
			seen := make(map[netip.Addr]struct{}, maxLearnedSources)
			for entry := router.recency.Front(); entry != nil; entry = entry.Next() {
				route := entry.Value.(*sourceRoute)
				if router.sources[route.source] != entry {
					t.Fatalf("LRU entry has no matching source: %v", route.source)
				}
				seen[route.source] = struct{}{}
			}
			if len(seen) != maxLearnedSources {
				t.Fatal("LRU retained duplicate sources")
			}
		})
	}
}

func assertRetentionSize(t *testing.T, router *packetRouter, want int) {
	t.Helper()
	router.mu.Lock()
	defer router.mu.Unlock()
	if got := len(router.sources); got != want || got > maxLearnedSources {
		t.Fatalf("source map size = %d, want %d", got, want)
	}
	if got := router.recency.Len(); got != want || got > maxLearnedSources {
		t.Fatalf("source LRU size = %d, want %d", got, want)
	}
}

func testRetentionAdmission(t *testing.T, first, destination netip.Addr) {
	t.Helper()
	tunnel, ctx := newRetentionDevice(t)
	router := tunnel.router
	source := first
	for i := range maxLearnedSources {
		router.mu.Lock()
		router.learnLocked(source, 1)
		router.mu.Unlock()
		assertRetentionSize(t, router, i+1)
		source = source.Next()
	}
	done := make(chan struct{})
	go func() { router.run(ctx, tunnel.stack, tunnel.cancel); close(done) }()
	t.Cleanup(func() { tunnel.cancel(); <-done })
	write := func(source netip.Addr, peer int) {
		tunnel.peer = peer
		packet := serverTestEchoPacket(destination, source)
		if n, err := tunnel.Write([][]byte{packet}, 0); n != 1 || err != nil {
			t.Fatalf("admission = %d, %v", n, err)
		}
		assertRetentionReply(t, ctx, router, peer, destination, source)
		assertRetentionSize(t, router, maxLearnedSources)
	}
	write(source, 0)
	if got := router.peerFor(first); got != 0 {
		t.Fatalf("evicted owner = %d, want 0", got)
	}
	if err := tunnel.stack.Inject(serverTestEchoPacket(destination, first), nil); err != nil {
		t.Fatal(err)
	}
	assertRetentionReply(t, ctx, router, 0, destination, first)
	router.mu.Lock()
	_, learned := router.sources[first]
	router.mu.Unlock()
	if learned {
		t.Fatal("outbound miss created a learned route")
	}
	invalid := bytes.Clone(serverTestEchoPacket(destination, first))
	if first.Is4() {
		invalid[10] ^= 0xff
	} else {
		invalid = invalid[:1]
	}
	if n, err := tunnel.Write([][]byte{invalid}, 0); n != 1 || err != nil {
		t.Fatalf("invalid packet result = %d, %v", n, err)
	}
	if got := router.peerFor(first); got != 0 {
		t.Fatalf("rejected packet changed fallback = %d", got)
	}
	router.mu.Lock()
	_, learned = router.sources[first]
	router.mu.Unlock()
	if learned {
		t.Fatal("invalid packet relearned an evicted source")
	}
	write(first, 1)
	if got := router.peerFor(first); got != 1 {
		t.Fatalf("admitted relearning owner = %d, want 1", got)
	}
	write(first, 0)
	if got := router.peerFor(first); got != 0 {
		t.Fatalf("last admitted sender = %d, want 0", got)
	}
	if err := tunnel.stack.Close(); err != nil {
		t.Fatal(err)
	}
	packet := serverTestEchoPacket(destination, source.Next())
	if n, err := tunnel.Write([][]byte{packet}, 0); n != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed stack admission = %d, %v", n, err)
	}
	<-done
	if _, learned := router.sources[source.Next()]; learned {
		t.Fatal("rejected admission learned a source")
	}
	assertRetentionSize(t, router, maxLearnedSources)
}

func assertRetentionReply(t *testing.T, ctx context.Context, router *packetRouter, peer int, source, destination netip.Addr) {
	t.Helper()
	select {
	case packet := <-router.queues[peer]:
		gotSource, gotDestination, valid := packetAddresses(packet)
		if diff := gocmp.Diff([]string{source.String(), destination.String()}, []string{gotSource.String(), gotDestination.String()}); !valid || diff != "" {
			t.Fatalf("reply addresses (-want +got):\n%s", diff)
		}
	case <-router.queues[1-peer]:
		t.Fatalf("reply reached peer %d, want %d", 1-peer, peer)
	case <-ctx.Done():
		t.Fatalf("routing reply did not complete: %v", ctx.Err())
	}
}
