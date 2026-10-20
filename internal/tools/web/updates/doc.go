// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package updates serves authenticated frontend WebSocket updates. Observations
// are copied/serialized under addon dispatch and enqueued without waiting for I/O.
// Each client has exactly 1024 ordinary message slots, one reader and one writer.
// Inbound messages are limited to 10 MiB and 1024 data fragments, including empty
// fragments; controls do not count. The next fragment closes with status 1009.
// Compression is disabled. Overflow selects 1011 without invalidating an in-flight
// frame; a 15-second grace bounds blocked writes before transport Abort.
package updates
