// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build race

package encoding

func init() { raceEnabled = true }
