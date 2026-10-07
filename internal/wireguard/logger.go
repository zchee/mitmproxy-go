// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"fmt"
	"log/slog"
	"strings"

	"golang.zx2c4.com/wireguard/device"
)

func deviceLogger(logger *slog.Logger) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) { logger.Debug(fmt.Sprintf(format, args...)) },
		Errorf: func(format string, args ...any) {
			message := fmt.Sprintf(format, args...)
			detail := message
			if strings.HasPrefix(detail, "peer(") {
				if _, text, ok := strings.Cut(detail, ") - "); ok {
					detail = text
				}
			}
			// An idle configured peer cannot initiate until its client supplies an
			// endpoint; this is normal while awaiting the first authenticated packet.
			if strings.HasPrefix(detail, "Failed to send handshake initiation: no known endpoint for peer") {
				logger.Debug(message)
				return
			}
			logger.Error(message)
		},
	}
}
