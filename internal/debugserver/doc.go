// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package debugserver owns opt-in loopback profiling and runtime diagnostics
// for one Master. Construct a Controller with a nonblocking telemetry Status
// capability, Bind it before addon registration, and add it to the default
// addons. Load and Configure do no network I/O; Running starts settled-option
// reconciliation. Call Close outside dispatch before closing log consumers.
package debugserver
