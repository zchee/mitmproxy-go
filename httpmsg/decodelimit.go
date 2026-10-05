// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg

import "sync/atomic"

// defaultDecodeLimit is the decoded-body bound before any SetDecodeLimit
// call: 256 MiB.
const defaultDecodeLimit int64 = 256 << 20

// decodeLimit holds the process-global decoded-body bound.
var decodeLimit = func() *atomic.Int64 {
	var v atomic.Int64
	v.Store(defaultDecodeLimit)
	return &v
}()

// DecodeLimit returns the current bound in bytes on the decoded size of a
// message body. The default is 256 MiB.
func DecodeLimit() int64 { return decodeLimit.Load() }

// SetDecodeLimit sets the bound in bytes on the decoded size of a message
// body and returns the previous bound. A body whose decoded size would
// exceed the bound counts as undecodable: [Message.Content] and
// [Message.Text] return an error and [Message.ContentOrRaw] and
// [Message.TextOrRaw] return the raw bytes. A zero bound only lets bodies
// that decode to nothing through, and a negative bound behaves as zero.
//
// The bound is process-global, because the decode paths are package-level
// code shared by every Master in the process: the last write wins. The
// core addon publishes the content_decode_limit option here.
func SetDecodeLimit(limit int64) (previous int64) { return decodeLimit.Swap(limit) }
