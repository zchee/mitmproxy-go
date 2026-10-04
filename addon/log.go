// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package addon

import "log/slog"

// LevelAlert is the alert log level. It has the urgency of info but asks
// interactive frontends to draw the user's attention to the entry even when
// the event log is not in view. It sits between [slog.LevelInfo] and
// [slog.LevelWarn], as mitmproxy's ALERT sits between INFO and WARNING.
const LevelAlert = slog.LevelInfo + 1

// LogEntry is a log record as the add_log hook receives it.
type LogEntry struct {
	// Msg is the formatted message.
	Msg string
	// Level is the record's level.
	Level slog.Level
}

// LevelName returns the mitmproxy name of the entry's level: "debug",
// "info", "alert", "warn" or "error".
//
// Only the five levels [slog.LevelDebug], [slog.LevelInfo], [LevelAlert],
// [slog.LevelWarn] and [slog.LevelError] have a name of their own; every
// other level is named "error", which is how mitmproxy names a record whose
// level is not one of its five.
func (e LogEntry) LevelName() string {
	switch e.Level {
	case slog.LevelDebug:
		return "debug"
	case slog.LevelInfo:
		return "info"
	case LevelAlert:
		return "alert"
	case slog.LevelWarn:
		return "warn"
	default:
		return "error"
	}
}
