// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tun

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

func configureDevice(root, name string, logger *slog.Logger) {
	if err := disableRPFilter(root, name, logger); err != nil {
		logger.Error(fmt.Sprintf("failed to set rp_filter: %v", err))
	}
	if err := os.WriteFile(filepath.Join(root, name, "route_localnet"), []byte("1"), 0o600); err != nil {
		logger.Error(fmt.Sprintf("Failed to enable route_localnet: %v", err))
	}
	if err := os.WriteFile(filepath.Join(root, name, "accept_local"), []byte("1"), 0o600); err != nil {
		logger.Error(fmt.Sprintf("Failed to enable accept_local: %v", err))
	}
}

func disableRPFilter(root, name string, logger *slog.Logger) error {
	if err := os.WriteFile(filepath.Join(root, name, "rp_filter"), []byte("0"), 0o600); err != nil {
		return fmt.Errorf("failed to disable rp_filter on the interface: %w", err)
	}
	conf, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("failed to read /proc/sys/net/ipv4/conf: %w", err)
	}
	defer func() { _ = conf.Close() }()
	globalPath := filepath.Join(root, "all", "rp_filter")
	global, err := conf.ReadFile(filepath.Join("all", "rp_filter"))
	if err != nil {
		return fmt.Errorf("failed to read /proc/sys/net/ipv4/conf/all/rp_filter: %w", err)
	}
	all := strings.TrimSpace(string(global))
	if all == "0" {
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("failed to read /proc/sys/net/ipv4/conf: %w", err)
	}
	for _, entry := range entries {
		if entry.Name() == name {
			continue
		}
		path := filepath.Join(root, entry.Name(), "rp_filter")
		// Upstream treats an unreadable per-interface value as empty and then
		// attempts to raise it to the global setting.
		data, _ := conf.ReadFile(filepath.Join(entry.Name(), "rp_filter"))
		current := strings.TrimSpace(string(data))
		combined := max(all, current)
		if combined != current {
			if err := os.WriteFile(path, []byte(combined), 0o600); err != nil {
				return fmt.Errorf("failed to set %s: %w", path, err)
			}
		}
	}
	// Do not lower the global setting unless all peer interfaces were updated.
	if err := os.WriteFile(globalPath, []byte("0"), 0o600); err != nil {
		return fmt.Errorf("failed to disable /proc/sys/net/ipv4/conf/all/rp_filter: %w", err)
	}
	logger.Debug("Successfully updated rp_filter.")
	return nil
}
