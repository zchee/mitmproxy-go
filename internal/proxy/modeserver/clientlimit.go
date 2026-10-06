// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import "sync/atomic"

// ClientLimiter reserves accepted clients across mode instances sharing it.
// Its zero value permits unlimited clients. Accepted clients retain their slots
// through handler cleanup; changing the limit does not interrupt them.
// All methods and mode-server admission are safe for concurrent use.
type ClientLimiter struct {
	limit  atomic.Int64
	active atomic.Int64
}

// SetLimit publishes the maximum concurrent accepted clients.
// A nonpositive limit is unlimited; already accepted clients remain live.
func (l *ClientLimiter) SetLimit(limit int) { l.limit.Store(int64(limit)) }

func (l *ClientLimiter) acquire() (bool, int64) {
	if l == nil {
		return true, 0
	}
	for {
		limit := l.limit.Load()
		active := l.active.Load()
		if limit > 0 && active >= limit {
			return false, limit
		}
		if l.active.CompareAndSwap(active, active+1) {
			return true, limit
		}
	}
}

func (l *ClientLimiter) release() {
	if l != nil {
		l.active.Add(-1)
	}
}
