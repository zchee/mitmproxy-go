// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

// Snapshot deep-copies close metadata and only the newest non-nil message.
// It returns nil for nil data; Messages contains at most one entry, never the
// accumulated history. Call under dispatch when d belongs to a live flow:
// this helper does not synchronize concurrent mutations.
func (d *Data) Snapshot() *Data {
	if d == nil {
		return nil
	}
	latest := *d
	latest.Messages = nil
	if n := len(d.Messages); n > 0 && d.Messages[n-1] != nil {
		latest.Messages = d.Messages[n-1:]
	}
	return latest.Clone()
}
