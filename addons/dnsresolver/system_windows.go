// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver

import (
	"errors"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

func systemConfiguration(_ string) (resolvConfig, error) {
	var cfg resolvConfig
	size := uint32(15 * 1024)
	for range 3 {
		if size > 1<<20 {
			return cfg, errors.New("Windows adapter configuration exceeds 1 MiB")
		}
		buffer := make([]byte, size)
		// GetAdaptersAddresses links records inside this live, aligned allocation.
		adapters := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, adapters, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if errors.Is(err, windows.ERROR_NO_DATA) {
			return cfg, nil
		}
		if err != nil {
			return cfg, err
		}
		for adapter := adapters; adapter != nil; adapter = adapter.Next {
			for server := adapter.FirstDnsServerAddress; server != nil; server = server.Next {
				if ip := server.Address.IP(); ip != nil {
					value := ip.String()
					if !slices.Contains(cfg.servers, value) {
						cfg.servers = append(cfg.servers, value)
					}
				}
			}
		}
		return cfg, nil
	}
	return cfg, errors.New("Windows adapter configuration kept changing")
}
