// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build clipboard

package export

import (
	"context"
	"log/slog"

	"golang.design/x/clipboard"
)

func copyClipboard(ctx context.Context, data []byte) error {
	if err := clipboard.Init(); err != nil {
		slog.ErrorContext(ctx, err.Error())
		return nil
	}
	if _, err := clipboard.Write(ctx, clipboard.FmtText, data); err != nil {
		slog.ErrorContext(ctx, err.Error())
	}
	return nil
}
