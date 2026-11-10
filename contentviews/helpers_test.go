// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import "log/slog"

// SetLogger replaces the package logger and returns the previous one.
// A nil logger uses slog.Default. Restore the returned value after temporary use.
func SetLogger(l *slog.Logger) *slog.Logger { return logger.Swap(l) }
