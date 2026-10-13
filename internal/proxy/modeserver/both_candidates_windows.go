// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build windows

package modeserver

import (
	"context"

	"github.com/zchee/mitmproxy-go/internal/netutil/freeport"
)

func bothPortCandidates(ctx context.Context) (portCandidateCursor, error) {
	return freeport.NewPortCandidates(ctx)
}
