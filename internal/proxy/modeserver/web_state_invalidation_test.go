// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"sync/atomic"
	"testing"
)

func TestWebPresentationInvalidation(t *testing.T) {
	tests := map[string]struct{ channel bool }{
		"nil channel is intentionally a no-op":       {},
		"coalesced sends still advance the revision": {channel: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			revision := new(atomic.Uint64)
			cfg.PresentationRevision = revision
			if tt.channel {
				changed := make(chan struct{}, 1)
				changed <- struct{}{}
				cfg.PresentationChanged = changed
			}
			instance := makeInstance(t, "regular@127.0.0.1:0", cfg)
			done := make(chan struct{})
			go func() { instance.signalPresentation(); instance.signalPresentation(); close(done) }()
			awaitWebPublication(t, done)
			if got := revision.Load(); got != 2 {
				t.Fatalf("coalesced invalidation revision = %d, want 2", got)
			}
		})
	}
}
