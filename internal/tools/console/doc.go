// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package console implements the terminal frontend's owned presentation state,
// dispatch bridge, key bindings and window layout.
//
// The executable uses Master.NewProgram to select terminal presentation ownership.
// In-memory harnesses use Master.NewModel and the bridge's DrainTo and
// DeliverEffectsTo commands with the harness program's sender and bridge context.
// Both entries share the same single-start workers and Close joins their lifetime.
package console
