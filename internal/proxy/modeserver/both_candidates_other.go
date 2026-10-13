// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !windows

package modeserver

import "context"

var bothPortCandidates func(context.Context) (portCandidateCursor, error)
