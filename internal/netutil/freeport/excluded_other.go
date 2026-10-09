// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !windows

package freeport

func isExcludedPort(int, bool) bool { return false }
