// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !windows

package dnsresolver

func systemConfiguration(path string) (resolvConfig, error) { return readResolvConf(path) }
