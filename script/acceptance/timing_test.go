// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build scripttiming

package acceptance_test

import "testing"

func TestScriptTiming(t *testing.T) {
	t.Run("timing", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"sleep_other_flow":      {func(t *testing.T) { otherFlow(t, false, true) }},
			"concurrent_other_flow": {func(t *testing.T) { otherFlow(t, true, true) }},
			"five_parallel":         {func(t *testing.T) { fiveParallel(t, true) }},
			"reload_inflight":       {func(t *testing.T) { reloadInflight(t, true) }},
			"nonblocking_parallel":  {func(t *testing.T) { nonblockingParallel(t, true) }},
			"mtime_reload":          {func(t *testing.T) { mtimeReload(t, true) }},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}
