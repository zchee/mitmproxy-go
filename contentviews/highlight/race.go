// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build race

package highlight

// raceMultiplier stretches the lexer deadline under the race detector, which
// slows the Chroma lexers by roughly 30x (a 200-line CSS file lexes in about
// 11 ms natively and 330 ms with -race), so ordinary inputs still highlight.
const raceMultiplier = 10
