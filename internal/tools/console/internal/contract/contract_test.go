// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contract

import (
	"slices"
	"testing"

	tea "charm.land/bubbletea/v2"
	gocmp "github.com/google/go-cmp/cmp"
)

func TestReplayPending(t *testing.T) {
	tests := map[string]struct {
		pending   []tea.Msg
		stop      int
		visited   []int
		remaining []tea.Msg
	}{
		"empty":        {},
		"drained":      {pending: []tea.Msg{1, 2}, visited: []int{1, 2}, remaining: []tea.Msg{}},
		"first stops":  {pending: []tea.Msg{1, 2}, stop: 1, visited: []int{1}, remaining: []tea.Msg{2}},
		"second stops": {pending: []tea.Msg{1, 2, 3}, stop: 2, visited: []int{1, 2}, remaining: []tea.Msg{3}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			pending := slices.Clone(test.pending)
			var visited []int
			cmd := ReplayPending(&pending, func(msg tea.Msg) (tea.Cmd, bool) {
				value := msg.(int)
				visited = append(visited, value)
				if value == test.stop {
					return func() tea.Msg { return value }, true
				}
				return nil, false
			})
			if diff := gocmp.Diff(test.visited, visited); diff != "" {
				t.Fatalf("visited (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(test.remaining, pending); diff != "" {
				t.Fatalf("remaining (-want +got):\n%s", diff)
			}
			if (cmd != nil) != (test.stop != 0) {
				t.Fatalf("command present = %t, stop = %d", cmd != nil, test.stop)
			}
			if cmd != nil && cmd() != test.stop {
				t.Fatal("returned a different command")
			}
		})
	}
}
