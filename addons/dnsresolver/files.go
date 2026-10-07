// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

func defaultHostsPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")
	}
	return "/etc/hosts"
}

func readHosts(path string) (map[string][]netip.Addr, error) {
	hosts := make(map[string][]netip.Addr)
	//nolint:gosec // The path is internal OS configuration, not DNS input.
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return hosts, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("hosts file exceeds 1 MiB")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(nil, (1<<20)+1)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		for _, name := range fields[1:] {
			name = canonicalName(name)
			if !slices.Contains(hosts[name], ip) {
				hosts[name] = append(hosts[name], ip)
			}
		}
	}
	return hosts, scanner.Err()
}

type resolvConfig struct{ servers []string }

func readResolvConf(path string) (resolvConfig, error) {
	var cfg resolvConfig
	//nolint:gosec // The path is internal OS configuration, not DNS input.
	file, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return cfg, err
	}
	if len(data) > 1<<20 {
		return cfg, errors.New("resolver configuration exceeds 1 MiB")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(nil, (1<<20)+1)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		line, _, _ = strings.Cut(line, ";")
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip, err := netip.ParseAddr(fields[1])
		if err == nil && !slices.Contains(cfg.servers, ip.String()) {
			cfg.servers = append(cfg.servers, ip.String())
		}
	}
	return cfg, scanner.Err()
}
