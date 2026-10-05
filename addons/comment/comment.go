// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package comment adds user comments to flows and notifies update handlers.
package comment

import (
	"context"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
)

// Comment owns the flow.comment command. Construct it with New.
type Comment struct{ manager *addon.Manager }

// New constructs a comment addon using manager to notify update handlers.
func New(manager *addon.Manager) *Comment { return &Comment{manager: manager} }

// Load registers flow.comment. The addon has no options.
func (c *Comment) Load(_ context.Context, loader *addon.Loader) error {
	return loader.AddCommand("flow.comment", c.Set, command.WithParams("flow", "comment"), command.WithHelp("Add a comment to a flow"))
}

// Set assigns comment to every supplied flow and fires one update hook, even for
// an empty selection. It must run under the addon dispatch lock with its context.
// It returns any error from dispatching the update.
func (c *Comment) Set(ctx context.Context, flows []flow.Flow, comment string) error {
	updated := make([]flow.Flow, 0, len(flows))
	for _, f := range flows {
		f.Common().Comment = comment
		updated = append(updated, f)
	}
	return c.manager.Trigger(ctx, addon.UpdateHook{Flows: updated})
}
