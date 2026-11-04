// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package view

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/options"
)

func TestViewHelp(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct {
			command string
			want    string
		}{
			"focus_go": {"view.focus.go", "Go to a specified offset. Positive offsets are from the beginning of\nthe view, negative from the end of the view, so that 0 is the first\nflow, -1 is the last flow."},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				manager := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{})
				defer manager.Close()
				must(t, manager.Add(t.Context(), New(manager)))
				var found *command.Command
				for name, registered := range manager.Commands().Commands() {
					if name == tt.command {
						found = registered
						break
					}
				}
				if found == nil {
					t.Fatalf("real view loader did not register %s", tt.command)
				}
				if diff := cmp.Diff(tt.want, found.Help); diff != "" {
					t.Fatalf("registered command help (-want +got):\n%s", diff)
				}
			})
		}
	})
}
