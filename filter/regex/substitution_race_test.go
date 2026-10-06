// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build race

package regex

func init() { substitutionRaceEnabled = true }
