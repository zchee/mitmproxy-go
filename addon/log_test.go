// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package addon

import (
	"log/slog"
	"testing"
)

func TestLogEntryLevelName(t *testing.T) {
	tests := map[string]struct {
		level slog.Level
		want  string
	}{
		"success: debug":                     {level: slog.LevelDebug, want: "debug"},
		"success: info":                      {level: slog.LevelInfo, want: "info"},
		"success: alert":                     {level: LevelAlert, want: "alert"},
		"success: warn":                      {level: slog.LevelWarn, want: "warn"},
		"success: error":                     {level: slog.LevelError, want: "error"},
		"success: level above error":         {level: slog.LevelError + 4, want: "error"},
		"success: level between alert, warn": {level: LevelAlert + 1, want: "error"},
		"success: level below debug":         {level: slog.LevelDebug - 4, want: "error"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := (LogEntry{Msg: "m", Level: tt.level}).LevelName(); got != tt.want {
				t.Errorf("LevelName() of %v = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}

func TestLevelOrder(t *testing.T) {
	if LevelAlert <= slog.LevelInfo || LevelAlert >= slog.LevelWarn {
		t.Errorf("LevelAlert = %v, want it between info and warn as mitmproxy orders ALERT", LevelAlert)
	}
}
