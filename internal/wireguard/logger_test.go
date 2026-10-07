// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestDeviceLogger(t *testing.T) {
	tests := map[string]struct {
		format  string
		args    []any
		verbose bool
		level   string
	}{
		"success: idle peer diagnostic is debug":      {format: "Failed to send handshake initiation: no known endpoint for peer", level: "DEBUG"},
		"success: pinned peer prefix is debug":        {format: "%v - Failed to send handshake initiation: %v", args: []any{"peer(test)", errors.New("no known endpoint for peer")}, level: "DEBUG"},
		"success: unrelated engine error stays error": {format: "Failed to receive packet: %v", args: []any{errors.New("transport failed")}, level: "ERROR"},
		"success: other handshake error stays error":  {format: "%v - Failed to send handshake initiation: %v", args: []any{"peer(test)", errors.New("transport failed")}, level: "ERROR"},
		"success: similar text is not demoted":        {format: "unrelated error: Failed to send handshake initiation: no known endpoint for peer", level: "ERROR"},
		"success: verbose remains debug":              {format: "device worker started", verbose: true, level: "DEBUG"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			logger := deviceLogger(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
			if test.verbose {
				logger.Verbosef(test.format, test.args...)
			} else {
				logger.Errorf(test.format, test.args...)
			}
			if !strings.Contains(output.String(), "level="+test.level+" ") {
				t.Errorf("device diagnostic = %q, want level %s", output.String(), test.level)
			}
		})
	}
}
