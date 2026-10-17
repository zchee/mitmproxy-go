// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !race

package highlight

// raceMultiplier keeps the production lexer deadline at its base value.
const raceMultiplier = 1
